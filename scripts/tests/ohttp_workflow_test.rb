# Copyright © 2026 Znewco, Inc. (d/b/a Zcash Open Development Lab)
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of ZODL Slipstream.
#
# ZODL Slipstream is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License,
# version 3 only, as published by the Free Software Foundation.
#
# ZODL Slipstream is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Affero General Public License for more details.
#
# Commercial licensing: see COMMERCIAL-LICENSE.md.

require "yaml"

root = File.expand_path("../..", __dir__)
workflow = YAML.load_file(File.join(root, ".github/workflows/ci.yml"))
action = YAML.load_file(File.join(root, ".github/actions/authorize-private-ohttp/action.yml"))
required = %w[GATEWAY_HOST RELAY_URL SIGNING_PUBKEY KEYS_DNS_NAME].flat_map do |kind|
  %w[MAINNET TESTNET].map { |network| "ZODL_OHTTP_#{kind}_#{network}" }
end
cargo_jobs = workflow.fetch("jobs").select do |_, job|
  job.fetch("steps", []).any? { |step| step.fetch("run", "").match?(/\bcargo (test|check|clippy|doc)\b/) }
end
raise "no Cargo jobs checked" if cargo_jobs.empty?
cargo_jobs.each do |name, job|
  effective = workflow.fetch("env", {}).merge(job.fetch("env", {}))
  required.each do |key|
    raise "#{name}: missing Actions variable #{key}" unless effective[key] == "${{ vars.#{key} }}"
  end
end
test_steps = workflow.fetch("jobs").fetch("test").fetch("steps")
raise "configuration variants are not run in CI" unless test_steps.any? do |step|
  step["run"] == "python3 scripts/tests/ohttp_configuration.py"
end
token = action.fetch("runs").fetch("steps").find { |step| step["id"] == "token" }
raise "wrong private repository token scope" unless token.fetch("with").fetch("repositories") == "zodl-ohttp"
manifest = File.read(File.join(root, "core/Cargo.toml"))
lock = File.read(File.join(root, "Cargo.lock"))
raise "old dependency URL" if [manifest, lock].any? { |text| text.include?("https://github.com/zodl-inc/ohttp.git") }
raise "final library missing" unless manifest.include?("https://github.com/zodl-inc/zodl-ohttp.git") && manifest.include?("650bb4ac5015dde96f22b67d7d77dc1020be9ed8")
puts "OHTTP workflow contract: #{cargo_jobs.length} Cargo jobs, eight variables, final dependency and token scope verified"
