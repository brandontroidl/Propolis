-- Interaction telemetry: how one exchange ended (the reason, the elapsed time, what the attacker
-- was told). Recorded in the ledger because it is evidence ABOUT the interaction, but never
-- scored: `SignalType::is_telemetry` classifies it, `repository::append_event` refuses it, and
-- both the incremental aggregates and `rebuild_projection` exclude these rows, so an outcome
-- record can move neither a score nor the breadth inputs a LATER scored event reads.
--
-- Additive only. PostgreSQL 12+ permits ALTER TYPE ... ADD VALUE inside a transaction as long as
-- the new value is not used in that same transaction; nothing here writes a row.
ALTER TYPE signal_type_enum ADD VALUE IF NOT EXISTS 'honeypot_session_end';
