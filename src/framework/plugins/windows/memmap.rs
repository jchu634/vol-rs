//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::windows::{kernel_module, physical_layer};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, pid_filter, pid_matches};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::{kernel_space_start, list_processes};

/// Prints the memory map
pub struct MemMap;

impl Plugin for MemMap {
    fn name(&self) -> &'static str {
        "windows.memmap.Memmap"
    }

    fn description(&self) -> &'static str {
        "Prints the memory map"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "pid",
                "Process ID to include (all other processes are excluded)",
                crate::framework::plugins::RequirementKind::Int,
            ),
            Requirement::new(
                "dump",
                "Extract listed memory segments",
                crate::framework::plugins::RequirementKind::Bool,
            )
            .with_default(crate::framework::context::ConfigValue::Bool(false)),
            Requirement::new(
                "user-memory",
                "List and extract only user memory; omit kernel mappings",
                crate::framework::plugins::RequirementKind::Bool,
            )
            .with_default(crate::framework::context::ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Virtual", ColumnType::UInt),
            Column::new("Physical", ColumnType::UInt),
            Column::new("Size", ColumnType::UInt),
            Column::new("Offset in File", ColumnType::UInt),
            Column::string("File output"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = physical_layer(config);
        let filter = pid_filter(config);
        let dump = config.get_bool("dump").unwrap_or(false);
        let user_memory = config.get_bool("user-memory").unwrap_or(false);

        // This plugin describes one process's map, so a filter selecting exactly
        // one process is what makes the output meaningful.
        let processes: Vec<_> = list_processes(&context, &kernel)?
            .into_iter()
            .filter(|process| {
                process
                    .pid()
                    .map(|pid| pid_matches(&filter, pid))
                    .unwrap_or(false)
            })
            .collect();

        if processes.is_empty() {
            return Err(VolatilityError::Other(
                "No process matched; memmap needs a --pid to describe".to_string(),
            ));
        }

        let mut columns = self.columns();
        if user_memory {
            columns.push(Column::new("User address limit", ColumnType::UInt));
        }
        let mut grid = TreeGrid::new(columns);
        for process in processes {
            let Ok(layer_name) = process.address_space(&physical) else {
                continue;
            };
            let layer = context.layers.get(&layer_name)?;
            let user_limit = user_memory.then(|| {
                user_address_limit(
                    layer.maximum_address(),
                    kernel_space_start(&context, &kernel),
                )
            });

            // The extracted file holds the mapped regions end to end, in the
            // order they are reported, so a row's offset says where in the
            // file its region landed. The file isn't actually created if it is
            // not needed.
            let pid = process.pid().unwrap_or(0);
            let file_name = format!("pid.{pid}.dmp");
            // The rows name the file as it was asked for, while what is
            // written keeps clear of a file of that name already there.
            let mut sink = if dump {
                crate::framework::plugins::create_output_file(
                    &crate::framework::plugins::free_extracted_name(&file_name),
                )
                .ok()
                .map(std::io::BufWriter::new)
            } else {
                None
            };

            // Walk the selected address space a page at a time, reporting the
            // regions that are actually mapped. `ignore_errors` skips the
            // unmapped stretches, which are the vast majority.
            let mut offset_in_file: u64 = 0;
            // The walk is windowed to keep it cheap over sparse space, but a
            // region that runs across a window boundary is still one region,
            // so the last one seen is held back until it is known whether the
            // next continues it.
            let mut pending: Option<crate::framework::layers::MappingEntry> = None;
            let mut address = layer.minimum_address();
            let maximum = user_limit.unwrap_or(layer.maximum_address());

            while address < maximum {
                // A large window keeps the walk cheap over sparse address space.
                let window = 0x1000_0000u64.min(maximum - address);
                let entries = match layer.mapping(&context.layers, address, window, true) {
                    Ok(entries) => entries,
                    Err(_) => break,
                };
                if entries.is_empty() {
                    address += window;
                    continue;
                }

                for entry in entries {
                    match &mut pending {
                        Some(last)
                            if last.offset + last.size == entry.offset
                                && last.mapped_offset + last.mapped_size == entry.mapped_offset
                                && last.layer == entry.layer =>
                        {
                            last.size += entry.size;
                            last.mapped_size += entry.mapped_size;
                        }
                        _ => {
                            if let Some(last) = pending.replace(entry) {
                                let written = write_region(&context, &layer_name, &last, &mut sink);
                                grid.push(
                                    0,
                                    region_row(
                                        &last,
                                        offset_in_file,
                                        dump,
                                        &file_name,
                                        written,
                                        user_limit,
                                    ),
                                )?;
                                offset_in_file += last.mapped_size;
                            }
                        }
                    }
                }
                address += window;
            }

            if let Some(last) = pending {
                let written = write_region(&context, &layer_name, &last, &mut sink);
                grid.push(
                    0,
                    region_row(&last, offset_in_file, dump, &file_name, written, user_limit),
                )?;
            }
        }
        Ok(grid)
    }
}

/// Exclusive user boundary, including Windows' configurable 32-bit /3GB split.
/// The x64 canonical gap must stay excluded even if kernel space starts above it.
fn user_address_limit(maximum: u64, kernel_start: u64) -> u64 {
    if maximum > u64::from(u32::MAX) {
        1 << 47
    } else if (0x8000_0000..=0xc000_0000).contains(&kernel_start)
        && kernel_start.is_multiple_of(4096)
    {
        kernel_start
    } else {
        1 << 31
    }
}

/// One mapped region, as this plugin reports it.
fn region_row(
    entry: &crate::framework::layers::MappingEntry,
    offset_in_file: u64,
    dump: bool,
    file_name: &str,
    written: bool,
    user_limit: Option<u64>,
) -> Vec<Value> {
    let output = if !dump {
        "Disabled".to_string()
    } else if written {
        file_name.to_string()
    } else {
        "Error outputting to file".to_string()
    };
    let mut row = vec![
        Value::hex(entry.offset),
        Value::hex(entry.mapped_offset),
        Value::hex(entry.mapped_size),
        Value::hex(offset_in_file),
        Value::string(output),
    ];
    if let Some(limit) = user_limit {
        row.push(Value::hex(limit));
    }
    row
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_boundary_excludes_the_x64_kernel_and_preserves_32_bit_splits() {
        assert_eq!(user_address_limit((1 << 48) - 1, 0xf800_0000_0000), 1 << 47);
        assert_eq!(user_address_limit(u32::MAX as u64, 0x8000_0000), 1 << 31);
        assert_eq!(
            user_address_limit(u32::MAX as u64, 0xc000_0000),
            0xc000_0000
        );
        assert_eq!(
            user_address_limit(u32::MAX as u64, 0xa000_0000),
            0xa000_0000
        );
        for invalid in [0, 0x7fff_0000, 0xffff_ffff, 0xa000_0001] {
            assert_eq!(user_address_limit(u32::MAX as u64, invalid), 1 << 31);
        }
    }

    #[test]
    fn full_dump_columns_stay_compatible_and_user_rows_record_the_limit() {
        let entry = crate::framework::layers::MappingEntry {
            offset: 0x9000_0000,
            size: 4096,
            mapped_offset: 4096,
            mapped_size: 4096,
            layer: "physical".into(),
        };
        assert_eq!(
            region_row(&entry, 0, true, "pid.1.dmp", true, None).len(),
            5
        );
        let row = region_row(&entry, 0, true, "pid.1.dmp", true, Some(1 << 47));
        assert!(matches!(row[5], Value::UInt(n, _) if n == 1 << 47));
        assert_eq!(MemMap.columns().len(), 5);
    }
}

/// Append one region's bytes to the file being written, if one is.
fn write_region(
    context: &Arc<Context>,
    layer_name: &str,
    entry: &crate::framework::layers::MappingEntry,
    sink: &mut Option<std::io::BufWriter<std::fs::File>>,
) -> bool {
    use std::io::Write;
    let Some(sink) = sink else { return false };
    let Ok(data) = context
        .layers
        .read(layer_name, entry.offset, entry.size as usize, true)
    else {
        return false;
    };
    sink.write_all(&data).is_ok()
}
