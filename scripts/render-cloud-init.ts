// Prints cloud-init.yaml rendered with sample values, for `cloud-init schema` in CI.
import { loadTemplate, renderCloudInit } from "../src/cloudinit.ts";

process.stdout.write(
  renderCloudInit(loadTemplate(), {
    adminUser: "ops",
    sshPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExample00 ops@example.com",
    rebootTime: "04:00",
  }),
);
