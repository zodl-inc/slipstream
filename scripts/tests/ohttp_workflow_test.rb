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
cargo_jobs = workflow.fetch("jobs").select do |_, job|
  job.fetch("steps", []).any? { |step| step.fetch("run", "").match?(/\bcargo (test|check|clippy|doc)\b/) }
end
raise "no Cargo jobs checked" if cargo_jobs.empty?
cargo_jobs.each do |name, job|
  steps = job.fetch("steps")
  authorize = steps.index { |step| step.fetch("uses", "") == "./.github/actions/authorize-private-ohttp" }
  raise "#{name}: private OHTTP authorization missing" unless authorize
  steps.each_with_index do |step, index|
    cache = step.fetch("uses", "").start_with?("Swatinem/rust-cache@")
    cargo = step.fetch("run", "").match?(/\bcargo (test|check|clippy|doc)\b/)
    raise "#{name}: cache/Cargo precedes private OHTTP authorization" if (cache || cargo) && index <= authorize
  end
end
raise "OHTTP build-time configuration remains in the workflow" if File.read(File.join(root, ".github/workflows/ci.yml")).include?("ZODL_" + "OHTTP")
token = action.fetch("runs").fetch("steps").find { |step| step["id"] == "token" }
raise "wrong private repository token scope" unless token.fetch("with").fetch("repositories") == "zodl-ohttp"
manifest = File.read(File.join(root, "core/Cargo.toml"))
lock = File.read(File.join(root, "Cargo.lock"))
raise "old dependency URL" if [manifest, lock].any? { |text| text.include?("https://github.com/zodl-inc/ohttp.git") }
raise "final library missing" unless manifest.include?("https://github.com/zodl-inc/zodl-ohttp.git") && manifest.include?("0f3eeb54e7d0aa22557ed5404a14e952d2ad3172") && lock.include?("#0f3eeb54e7d0aa22557ed5404a14e952d2ad3172")
puts "OHTTP workflow contract: #{cargo_jobs.length} Cargo jobs, private authorization order, final dependency and token scope verified"
