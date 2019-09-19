# FedPI Nodes
FedPI nodes run with Tendermint (version 0.32.3)

# Tendermint Reset
tendermint unsafe_reset_all --home ./test-net/node0
tendermint unsafe_reset_all --home ./test-net/node1
tendermint unsafe_reset_all --home ./test-net/node2
tendermint unsafe_reset_all --home ./test-net/node3

# Tendermint Setup
tendermint node --home ./test-net/node0
tendermint node --home ./test-net/node1
tendermint node --home ./test-net/node2
tendermint node --home ./test-net/node3

# Tendermint Testing
curl -s localhost:26657/status