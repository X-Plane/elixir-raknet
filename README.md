# Elixir RakNet

**`main` build status**: [![main build status](https://circleci.com/gh/X-Plane/elixir-raknet/tree/main.svg?style=svg)](https://circleci.com/gh/X-Plane/elixir-raknet/tree/main) **Latest commit build status**: [![Last commit build status](https://circleci.com/gh/X-Plane/elixir-raknet.svg?style=svg)](https://circleci.com/gh/X-Plane/elixir-raknet)

This is an Elixir implementation of the [RakNet](https://github.com/facebookarchive/RakNet)/RakLib networking communication protocol.

It offers things like stateful connections, reliable (or unreliable) UDP transmissions, and client clock synchronization, all of which are generally necessary for implementing a multiplayer game server. 

Note that this is not a *complete* implementation of the RakNet protocol—it currently offers only what X-Plane needs for its massive multiplayer server. Known limitations include:

1. The server doesn't do well with retransmitting unacknowledged reliable packets, since we only ever send unreliable packets in our MMO server. 
2. We don't support splitting packets larger than the connection's MTU size—this leaves the responsibility on the client to make sure your packets aren't over the size limit (which of course can vary depending on the client's connection—yikes!). In practice, this isn't a problem if you know your packets are reasonably small (well under 1 KB).

We'd welcome well-tested pull requests to fix these things, though. (See the [Contributing](#contributing) section below.)

## Installation

Add `raknet` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:raknet, git: "https://github.com/X-Plane/elixir-raknet.git", branch: "main"},
  ]
end
```

## Usage

In your application, you'll need two things:

1. A client state struct that implements the `RakNet.Client` protocol. For the X-Plane massive multiplayer server, our state struct looks like this:

        defmodule MmoServer.Client.State do
          @moduledoc "State for our implementation of RakNet.Client"
          @enforce_keys [:session_id, :connection_pid]
          defstruct session_id: -1,
                    connection_pid: nil,
                    # Other fields, which get default-initialized
                    # when a new connection is negotiated. 
                    . . . 
        end

    Then, in our implementation of the `RakNet.Client` protocol, we spin up a GenServer for each connection as follows:

        defimpl RakNet.Client, for: MmoServer.Client.State do
          def new(_client_struct, connection_pid, _) do
            new_state = %MmoServer.Client.State{
              connection_pid: connection_pid,
              session_id: MmoServer.SessionIdServer.new_id()
            }
   
            MmoServer.Client.start_link(new_state)
            new_state
          end
        
          def receive(%MmoServer.Client.State{session_id: id}, packet_type, packet_buffer, transit_time) do
            MmoServer.Client.handle_packet(id, packet_type, packet_buffer, transit_time)
          end
        
          def got_ack(%MmoServer.Client.State{session_id: _id}, _send_receipt_id) do
            # X-Plane doesn't actually do anything with packet acknowledgements
            nil
          end
        
          def disconnect(%MmoServer.Client.State{session_id: id}) do
            MmoServer.Client.disconnect(id)
          end
        end
   
2. One or more `RakNet.Server` GenServers (one per port you want to accept connections on). For the X-Plane MMO server, we accept connections on a range of ports, like this:

        localhost = {127, 0, 0, 1}
   
        make_server_spec = fn port ->
          # Only your client state type and port are required 
          [MmoServer.Client.State, port, include_timestamp_with_datagrams: true, host: localhost, client_timeout_ms: 20 * 60 * 1_000, open_ipv6_socket: true]
        end
     
        servers =
          Enum.map(port_min..port_max, fn port ->
            {RakNet.Server, make_server_spec.(port)}
          end)
    
        opts = [strategy: :one_for_one, name: MmoServer.Supervisor]
   
        Supervisor.start_link(servers, opts)

One configuration option above is worth calling out explicitly: the value of `:open_ipv6_socket` will determine whether we try to open a *separate* socket to receive IPv6 connections, or whether we accept IPv6 connections over the same socket as IPv4. The configuration you need here will depend on your OS configuration, but in general, Linux systems default to sharing a socket, while macOS defaults to using separate sockets. Alternatively, you can set a default value for this using the `SEPARATE_IPV6_PORT` environment variable.

From this point forward, the `RakNet.Server` will create a new stateful `RakNet.Connection` for each RakNet client that connects on your port, and client packets will be forwarded to your client struct.

The client can send messages using the `connection_pid` it was constructed with, like so:

    RakNet.Connection.send(state.connection_pid, :reliable, packet)

...where the final argument is a bitstring, and the second argument is the reliability level the packet should be transmitted with. Supported reliability levels are defined in `RakNet.ReliabilityLayer.Reliability` as:

- `:unreliable`
- `:unreliable_sequenced`
- `:reliable`
- `:reliable_ordered`
- `:reliable_sequenced`
- `:unreliable_ack_receipt`
- `:reliable_ack_receipt`
- `:reliable_ordered_ack_receipt` 

## Running the tests

You can run the complete unit test suite via the standard `$ mix test` from the top-level directory. Note that you'll see a log message about receiving data before the connection negotiation finished—that's deliberate, since we test handling that error case, but it would be somewhat concerning for it to occur in production.

[We use CircleCI](https://app.circleci.com/pipelines/github/X-Plane/elixir-raknet) to run the test suite on every commit.

You can run the same tests that CircleCI does as follows:

1. Run the Credo linter: `$ mix credo --strict`
2. Confirm the code matches the official formatter: `$ mix format --check-formatted`
3. Confirm the tests pass: `$ mix test` (or if you like more verbose output, `$ mix test --trace`)

## Contributing

Before submitting a pull request, please ensure:

1. You've added appropriate tests for your new changes
2. All tests pass
3. The credo analysis is clean: `$ mix credo --strict --ignore tagtodo`
4. You've run `$ mix format`
