// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! A byte queue, one per direction.
//!
//! picobootx asks its transport for bytes and offers it bytes, and an
//! endpoint moves packets.  These sit between the two: the driver task fills
//! one and drains the other a packet at a time, and the protocol reads and
//! writes whatever length it is working in.

pub(crate) struct Fifo<const N: usize> {
    buf: [u8; N],
    head: usize,
    len: usize,
}

impl<const N: usize> Fifo<N> {
    pub(crate) const fn new() -> Self {
        Self {
            buf: [0; N],
            head: 0,
            len: 0,
        }
    }

    /// How many bytes are queued.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// How many more will fit.
    pub(crate) fn free(&self) -> usize {
        N - self.len
    }

    /// Drop everything queued.
    pub(crate) fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    /// Queue what fits, and say how much that was.
    pub(crate) fn write(&mut self, src: &[u8]) -> usize {
        let n = src.len().min(self.free());
        for (i, b) in src[..n].iter().enumerate() {
            self.buf[(self.head + self.len + i) % N] = *b;
        }
        self.len += n;
        n
    }

    /// Take what is asked for or what there is, and say how much that was.
    pub(crate) fn read(&mut self, dst: &mut [u8]) -> usize {
        let n = dst.len().min(self.len);
        for (i, b) in dst[..n].iter_mut().enumerate() {
            *b = self.buf[(self.head + i) % N];
        }
        self.head = (self.head + n) % N;
        self.len -= n;
        n
    }
}
