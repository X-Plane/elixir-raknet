defmodule RakNet.MixProject do
  use Mix.Project

  def project do
    [
      app: :raknet,
      version: "0.1.0",
      build_path: "_build",
      deps_path: "deps",
      lockfile: "mix.lock",
      elixir: "~> 1.11",
      elixirc_options: [warnings_as_errors: halt_on_warnings?(Mix.env())],
      start_permanent: Mix.env() == :prod,
      consolidate_protocols: Mix.env() != :test,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {RakNet.Application, []}
    ]
  end

  defp deps do
    [
      {:x_util, git: "https://github.com/X-Plane/elixir-xutil.git", branch: "main"},
      {:socket, "~> 0.3.13"},
      {:assertions, "~> 0.10", only: :test},
      {:credo, "~> 1.5.1", only: [:dev, :test], runtime: false}
    ]
  end

  # Clever hack to allow unused functions and the like in test, but not dev or prod:
  # https://blog.rentpathcode.com/elixir-warnings-as-errors-sometimes-f5a8d2c96b15
  defp halt_on_warnings?(:test), do: false
  defp halt_on_warnings?(_), do: true
end
