//! Definition of the lable type which can be used as jump target and can be bound to a location in
//! the emitted code.

use hashbrown::HashSet;

/// A label which is used as target for jump instructions.
///
/// ```rust
/// use juicebox_asm::prelude::*;
///
/// let mut lbl = Label::new();
/// let mut asm = Asm::new();
///
/// // Skip the mov instruction.
/// asm.jmp(&mut lbl);
/// asm.mov(Reg64::rax, Reg64::rax);
/// asm.bind(&mut lbl);
/// ```
///
/// # Panics
///
/// Panics if the label is dropped while not yet bound, or having unresolved relocations.
/// This is mainly a safety-guard to detect wrong usage.
pub struct Label {
    /// Location of the label. Will be set after the label is bound, else None.
    location: Option<usize>,

    /// Offsets that must be patched with the label location.
    offsets: HashSet<usize>,
}

impl Default for Label {
    fn default() -> Self {
        Self::new()
    }
}

impl Label {
    /// Create a new `unbound` [Label].
    pub fn new() -> Label {
        Label {
            location: None,
            offsets: HashSet::new(),
        }
    }

    /// Bind the label to the `location`, can only be bound once.
    ///
    /// # Panics
    ///
    /// Panics if the lable is already bound.
    pub(crate) fn bind(&mut self, loc: usize) {
        // A label can only be bound once!
        assert!(!self.is_bound());

        self.location = Some(loc);
    }

    /// Record an offset that must be patched with the label location.
    pub(crate) fn record_offset(&mut self, off: usize) {
        self.offsets.insert(off);
    }

    /// Get the location of the lable if already bound, `None` else.
    pub(crate) fn location(&self) -> Option<usize> {
        self.location
    }

    /// Get the offsets which refer to the label. These are used to patch the jump instructions to
    /// the label location.
    pub(crate) fn offsets_mut(&mut self) -> &mut HashSet<usize> {
        &mut self.offsets
    }

    /// Check whether the label is bound to a location.
    const fn is_bound(&self) -> bool {
        self.location.is_some()
    }
}

impl Drop for Label {
    fn drop(&mut self) {
        // Ensure the label was bound when it is dropped.
        assert!(self.is_bound());
        // Ensure all offsets have been patched when the label is dropped.
        assert!(self.offsets.is_empty());
    }
}
