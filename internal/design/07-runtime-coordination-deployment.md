# 07 - Runtime composition + multi-node coordination + deployment

Status: design pending (not yet brainstormed)

## Scope

The composition root that wires the process and its background jobs, the process model for single-node and cluster deployments, scheduler leader-election so cluster nodes do not double-fire scheduled work, the tamper-evident audit wiring, and the hardened deployment units and install path.

## Goals

Make the system deployable and coordinated. One composition root wires the layers below into a running process. In a cluster, scheduled jobs run once across the set, not once per node. Cluster purpose stays signal aggregation; replication and failover are a secondary benefit of PostgreSQL, not the driver. Deployment units carry the hardened, least-privilege shape by default, never a weakly-hardened generated unit.

## Dependencies

All prior sub-projects: this layer composes and runs them.

## Key open questions

- Coordination mechanism for leader-election across nodes.
- Deployment target and the shape of the install and service units.
- HA failover behavior: what a node loss does to scoring, intake, and the scheduled jobs, given that aggregation, not uptime, is the cluster's purpose.
