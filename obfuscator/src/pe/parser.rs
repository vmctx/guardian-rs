// full credits go to https://github.com/unknowntrojan/mapparse

use anyhow::{Context, Result};
use symbolic_demangle::Demangle;

#[derive(Clone)]
pub struct Rva(pub usize);

#[derive(Clone)]
pub struct Address {
    pub seg: u16,
    pub addr: usize,
}

#[derive(Debug)]
enum Class {
    Code,
    Data,
}

pub struct Section {
    name: String,
    class: Class,
    addr: Address,
    len: usize,
}

#[derive(Clone, Debug)]
pub enum LibObject {
    LibObj(Option<String>, String),
    Absolute,
}

pub struct Function {
    pub symbol: String,
    pub addr: Address,
    pub rva: Rva,
    pub flags: Vec<String>,
    pub libobj: LibObject,
}

pub struct StaticSymbol {
    pub symbol: String,
    pub addr: Address,
    pub rva: Rva,
    pub flags: Vec<String>,
    pub libobj: LibObject,
}

pub struct MapFile {
    pub file_name: String,
    pub entrypoint: Address,
    pub preferred_load_addr: usize,
    pub timestamp: String,
    pub sections: Vec<Section>,
    pub functions: Vec<Function>,
    pub static_symbols: Vec<StaticSymbol>,
}

type Size = usize;

impl MapFile {
    pub fn load(input: &str) -> Result<Self> {
        #[derive(Debug)]
        enum Stage {
            Header,
            Sections,
            Functions,
            StaticSymbols,
        }

        let mut stage = Stage::Header;

        let mut filename: Option<&str> = None;
        let mut timestamp: Option<&str> = None;
        let mut load_address: Option<usize> = None;
        let mut entry_point: Option<Address> = None;
        let mut sections: Vec<Section> = Default::default();
        let mut functions: Vec<Function> = Default::default();
        let mut static_symbols: Vec<StaticSymbol> = Default::default();

        for (line, data) in input.split("\r\n").enumerate() {
            // we are using zero-based indices, but i would like to use editor line numbers
            // using line numbers in general is yucky, but there is for example no clean way for me
            // to know which line the filename line is, as it does not contain anything else
            let line = line + 1;

            match stage {
                Stage::Header => match line {
                    1 => filename = Some(data.trim()),
                    3 => {
                        let begin = data.find('(').context("there was no timestamp on line 3")?;
                        let end = data.find(')').context("there was no timestamp on line 3")?;

                        timestamp = Some(&data[begin + 1..end - 1])
                    }
                    5 => {
                        load_address = Some(
                            usize::from_str_radix(
                                &data[data.find("is ").context(
                                    "there was no preferred load address statement on line 5",
                                )? + 3..],
                                16,
                            )
                                .context("unable to get preferred load address from line 5")?,
                        )
                    }
                    7 => stage = Stage::Sections,
                    _ => {}
                },
                Stage::Sections => {
                    if data.contains("Publics by Value") {
                        stage = Stage::Functions;
                        continue;
                    }

                    // hacky way to know we are on an actual data line
                    if !data.contains('0') {
                        continue;
                    }

                    enum SectionStage {
                        Address,
                        Length,
                        Symbol,
                        Class,
                    }

                    let mut section_stage = SectionStage::Address;

                    let mut address: Option<Address> = None;
                    let mut length: Option<usize> = None;
                    let mut symbol: Option<&str> = None;
                    let mut class: Option<Class> = None;

                    for substring in data.split(' ') {
                        if substring.is_empty() {
                            continue;
                        }

                        match section_stage {
                            SectionStage::Address => {
                                let addrstr: Vec<&str> = substring.split(':').collect();

                                // these will panic if the format is invalid
                                let seg = addrstr[0];
                                let addr = addrstr[1];

                                address = Some(Address {
                                    seg: seg.parse().context("unable to parse segment")?,
                                    addr: usize::from_str_radix(addr, 16)
                                        .context("unable to parse address")?,
                                });

                                section_stage = SectionStage::Length;
                            }
                            SectionStage::Length => {
                                length = Some(
                                    usize::from_str_radix(&substring[0..substring.len() - 1], 16)
                                        .context("unable to parse length")?,
                                );

                                section_stage = SectionStage::Symbol;
                            }
                            SectionStage::Symbol => {
                                symbol = Some(substring);

                                section_stage = SectionStage::Class;
                            }
                            SectionStage::Class => {
                                class = Some(match substring {
                                    "CODE" => Class::Code,
                                    "DATA" => Class::Data,
                                    _ => {
                                        panic!("unrecognized section class {}", substring);
                                    }
                                });
                            }
                        }
                    }

                    sections.push(Section {
                        addr: address.context("no address was found")?,
                        len: length.context("no length was found")?,
                        name: symbol.context("no symbol was found")?.to_string(),
                        class: class.context("no class was found")?,
                    })
                }
                Stage::Functions => {
                    if data.contains("entry point at") {
                        stage = Stage::StaticSymbols;

                        for substring in data.split(' ') {
                            if substring.is_empty() {
                                continue;
                            }

                            if substring.contains('0') {
                                let addrstr: Vec<&str> = substring.split(':').collect();

                                // these will panic if the format is invalid
                                let seg = addrstr[0];
                                let addr = addrstr[1];

                                entry_point = Some(Address {
                                    seg: seg.parse().context("unable to parse segment")?,
                                    addr: usize::from_str_radix(addr, 16)
                                        .context("unable to parse address")?,
                                });
                            }
                        }

                        continue;
                    }

                    // hacky way to know we are on an actual data line
                    if !data.contains('0') {
                        continue;
                    }

                    enum FunctionStage {
                        Address,
                        Symbol,
                        Rva,
                        LibObj,
                    }

                    let mut function_stage = FunctionStage::Address;
                    let mut address: Option<Address> = None;
                    let mut symbol: Option<&str> = None;
                    let mut rva: Option<Rva> = None;
                    let mut flags: Vec<String> = Default::default();
                    let mut libobj: Option<LibObject> = None;

                    for substring in data.split(' ') {
                        if substring.is_empty() {
                            continue;
                        }

                        match function_stage {
                            FunctionStage::Address => {
                                let addrstr: Vec<&str> = substring.split(':').collect();

                                // these will panic if the format is invalid
                                let seg = addrstr[0];
                                let addr = addrstr[1];

                                address = Some(Address {
                                    seg: seg.parse().context("unable to parse segment")?,
                                    addr: usize::from_str_radix(addr, 16)
                                        .context("unable to parse address")?,
                                });

                                function_stage = FunctionStage::Symbol;
                            }
                            FunctionStage::Symbol => {
                                symbol = Some(substring);
                                function_stage = FunctionStage::Rva
                            }
                            FunctionStage::Rva => {
                                let rva_with_base = usize::from_str_radix(substring, 16)
                                    .context("unable to parse rva")?;

                                let val = if rva_with_base == 0 {
                                    0
                                } else {
                                    rva_with_base.wrapping_sub(load_address.unwrap())
                                };

                                rva = Some(Rva(val));
                                function_stage = FunctionStage::LibObj;
                            }
                            FunctionStage::LibObj => {
                                match substring.contains("<absolute>") {
                                    true => libobj = Some(LibObject::Absolute),
                                    false => {
                                        // this is code responsible for both LibObj and flags cases.
                                        // this is a bit retarded, but we can't have a flag state,
                                        // as we would need to switch match cases which isn't possible
                                        // as we don't have goto.
                                        match substring.len() {
                                            1 => {
                                                // FLAG!
                                                flags.push(substring.to_string())
                                            }
                                            _ => {
                                                let libobjstr: Vec<&str> =
                                                    substring.split(':').collect();

                                                match libobjstr.len() {
                                                    1 => {
                                                        libobj = Some(LibObject::LibObj(
                                                            None,
                                                            libobjstr[0].to_string(),
                                                        ))
                                                    }
                                                    _ => {
                                                        libobj = Some(LibObject::LibObj(
                                                            Some(libobjstr[0].to_string()),
                                                            libobjstr[1].to_string(),
                                                        ))
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    functions.push(Function {
                        addr: address.context("no address was found")?,
                        symbol: symbolic_common::Name::from(symbol.context("no symbol was found")?).
                            try_demangle(symbolic_demangle::DemangleOptions::name_only()).to_string(),
                        rva: rva.context("no rva was found")?,
                        flags,
                        libobj: libobj.context("no libobj was found")?,
                    })
                }
                Stage::StaticSymbols => {
                    // reused code from function stage

                    // hacky way to know we are on an actual data line
                    if !data.contains('0') {
                        continue;
                    }

                    enum FunctionStage {
                        Address,
                        Symbol,
                        Rva,
                        LibObj,
                    }

                    let mut function_stage = FunctionStage::Address;
                    let mut address: Option<Address> = None;
                    let mut symbol: Option<&str> = None;
                    let mut rva: Option<Rva> = None;
                    let mut flags: Vec<String> = Default::default();
                    let mut libobj: Option<LibObject> = None;

                    for substring in data.split(' ') {
                        if substring.is_empty() {
                            continue;
                        }

                        match function_stage {
                            FunctionStage::Address => {
                                let addrstr: Vec<&str> = substring.split(':').collect();

                                // these will panic if the format is invalid
                                let seg = addrstr[0];
                                let addr = addrstr[1];

                                address = Some(Address {
                                    seg: seg.parse().context("unable to parse segment")?,
                                    addr: usize::from_str_radix(addr, 16)
                                        .context("unable to parse address")?,
                                });

                                function_stage = FunctionStage::Symbol;
                            }
                            FunctionStage::Symbol => {
                                symbol = Some(substring);
                                function_stage = FunctionStage::Rva
                            }
                            FunctionStage::Rva => {
                                let rva_with_base = usize::from_str_radix(substring, 16)
                                    .context("unable to parse rva")?;

                                let val = if rva_with_base == 0 {
                                    0
                                } else {
                                    rva_with_base - load_address.unwrap()
                                };

                                rva = Some(Rva(val));
                                function_stage = FunctionStage::LibObj;
                            }
                            FunctionStage::LibObj => {
                                match substring.contains("<absolute>") {
                                    true => libobj = Some(LibObject::Absolute),
                                    false => {
                                        // this is code responsible for both LibObj and flags cases.
                                        // this is a bit retarded, but we can't have a flag state,
                                        // as we would need to switch match cases which isn't possible
                                        // as we don't have goto.
                                        match substring.len() {
                                            1 => {
                                                // FLAG!
                                                flags.push(substring.to_string())
                                            }
                                            _ => {
                                                if substring.len() < 3 {
                                                    dbg!(substring.len());
                                                }

                                                let libobjstr: Vec<&str> =
                                                    substring.split(':').collect();

                                                match libobjstr.len() {
                                                    1 => {
                                                        libobj = Some(LibObject::LibObj(
                                                            None,
                                                            libobjstr[0].to_string(),
                                                        ))
                                                    }
                                                    _ => {
                                                        libobj = Some(LibObject::LibObj(
                                                            Some(libobjstr[0].to_string()),
                                                            libobjstr[1].to_string(),
                                                        ))
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    static_symbols.push(StaticSymbol {
                        addr: address.context("no address was found")?,
                        symbol: symbolic_common::Name::from(symbol.context("no symbol was found")?)
                            .try_demangle(symbolic_demangle::DemangleOptions::name_only()).to_string(),
                        rva: rva.context("no rva was found")?,
                        flags,
                        libobj: libobj.context("no libobj was found")?,
                    })
                }
            }
        }

        Ok(MapFile {
            file_name: filename.context("filename not found")?.to_string(),
            entrypoint: entry_point.context("entrypoint not found")?,
            preferred_load_addr: load_address.context("preferred load address not found")?,
            timestamp: timestamp.context("timestamp not found")?.to_string(),
            sections,
            functions,
            static_symbols,
        })
    }

    pub fn get_function(&self, function_name: &str) -> Option<(Function, Size)> {
        let mut found_function = None;
        let mut size = 0;

        for function in &self.functions {
            if function.flags.contains(&"f".to_string()) && function.symbol.eq(function_name) {
                found_function = Some(Function {
                    symbol: function.symbol.clone(),
                    addr: function.addr.clone(),
                    rva: function.rva.clone(),
                    flags: function.flags.clone(),
                    libobj: function.libobj.clone(),
                });
                break;
            }

        }

        for function in &self.static_symbols {
            if function.flags.contains(&"f".to_string()) && function.symbol.eq(function_name) {
                found_function = Some(Function {
                    symbol: function.symbol.clone(),
                    addr: function.addr.clone(),
                    rva: function.rva.clone(),
                    flags: function.flags.clone(),
                    libobj: function.libobj.clone(),
                });
                break;
            }

        }

        if let Some(found_function) = &found_function {
            size = self.find_next_function(found_function.rva.0) - found_function.rva.0;
        }

        Some((found_function?, size))
    }

    fn find_next_function(&self, rva: usize) -> usize {
        let mut found_rva = 0;
        for function in &self.functions {
            if function.rva.0 > rva && (function.rva.0 < found_rva || found_rva == 0) {
                found_rva = function.rva.0
            }
        }

        for function in &self.static_symbols {
            if function.rva.0 > rva && (function.rva.0 < found_rva || found_rva == 0) {
                found_rva = function.rva.0
            }
        }

        found_rva
    }
}