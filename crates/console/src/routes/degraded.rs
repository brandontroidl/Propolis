//! The soft-fail ledger for a page render. Several pages deliberately let a supplementary panel
//! fail without taking the page down (`routes::dashboard`'s and `routes::context`'s doc comments
//! own that policy). What that policy used to do silently was render the failure as data: a query
//! error became "0 events", an empty chart, "not linked", "not yet scanned" - indistinguishable
//! from a healthy node that has simply seen nothing. Every soft failure now goes through
//! [`Degraded::soft`], which logs the real error and records the panel's name, and the page
//! layout renders the names as a banner so the operator sees WHICH panels are placeholders.

/// Panels a page could not load, in the order they failed.
#[derive(Debug, Default)]
pub(crate) struct Degraded(Vec<&'static str>);

impl Degraded {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The panel's value on success; on failure, log the error, record `what`, and hand back
    /// `fallback` for the template's placeholder rendering.
    pub(crate) fn soft_or<T, E: std::fmt::Display>(
        &mut self,
        what: &'static str,
        result: Result<T, E>,
        fallback: T,
    ) -> T {
        match result {
            Ok(v) => v,
            Err(error) => {
                tracing::warn!(panel = what, %error, "console: panel unavailable, rendering a placeholder");
                self.0.push(what);
                fallback
            }
        }
    }

    /// [`Self::soft_or`] with the type's default (an empty list, `None`, zero) as the placeholder.
    pub(crate) fn soft<T: Default, E: std::fmt::Display>(
        &mut self,
        what: &'static str,
        result: Result<T, E>,
    ) -> T {
        self.soft_or(what, result, T::default())
    }

    /// Record a failure that did not come through a `Result` (a missing file where one was
    /// expected, say).
    pub(crate) fn note(&mut self, what: &'static str) {
        tracing::warn!(
            panel = what,
            "console: panel unavailable, rendering a placeholder"
        );
        self.0.push(what);
    }

    /// Fold another ledger's failures into this one (a page merging `base_context`'s).
    pub(crate) fn absorb(&mut self, other: Degraded) {
        self.0.extend(other.0);
    }

    /// The panel names, for the template's banner. Empty when the page rendered whole.
    pub(crate) fn names(&self) -> Vec<&'static str> {
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_passes_the_value_through_and_records_nothing() {
        let mut d = Degraded::new();
        let v: i64 = d.soft("events", Ok::<i64, String>(7));
        assert_eq!(v, 7);
        assert!(d.names().is_empty());
    }

    #[test]
    fn err_yields_the_placeholder_and_records_the_panel() {
        let mut d = Degraded::new();
        let v: i64 = d.soft_or("events last hour", Err::<i64, String>("boom".into()), -1);
        assert_eq!(v, -1);
        let rows: Vec<u8> = d.soft("recent events", Err::<Vec<u8>, String>("down".into()));
        assert!(rows.is_empty());
        assert_eq!(d.names(), vec!["events last hour", "recent events"]);
    }

    #[test]
    fn absorb_keeps_order_across_ledgers() {
        let mut base = Degraded::new();
        base.note("pending review count");
        let mut page = Degraded::new();
        page.note("event count");
        page.absorb(base);
        assert_eq!(page.names(), vec!["event count", "pending review count"]);
    }
}
