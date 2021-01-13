defmodule RakNet.Application do
  @moduledoc "Supervision tree for RakNet connections"

  use Application

  def start(_type, _args) do
    Logger.configure(
      level:
        case(System.fetch_env("LOG_LEVEL")) do
          {:ok, "debug"} -> :debug
          {:ok, "info"} -> :info
          {:ok, "warn"} -> :warn
          {:ok, "error"} -> :error
          _ -> :info
        end
    )

    children = [
      {Registry, keys: :unique, name: RakNet.Connection}
    ]

    opts = [strategy: :one_for_one, name: RakNet.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
