defmodule ExplicitlyIgnoreReturnValues do
  @moduledoc """
  This is a horrifying hack.

  It is a complete copy & paste of Credo's stock unused_operation and unused_function_return_helper,
  but modified slightly to reverse the logic; instead of specifying modules and types to warn about when unused,
  we specify an "allow list" of the *only* modules & functions to allow ignoring.

  See original copypasta source here:
  https://github.com/rrrene/credo/blob/master/lib/credo/check/warning/unused_operation.ex
  https://github.com/rrrene/credo/blob/master/lib/credo/check/warning/unused_function_return_helper.ex
  """

  @funs_to_allow_ignoring [
    {[:Enum], :each},
    {[:GenServer], :cast},
    {[:GenServer], :stop},
    {[:IO], :inspect},
    {[:IO], :puts},
    {[:IO], :warn},
    {[:IO], :write},
    {[:Logger], :configure},
    {[:Logger], :debug},
    {[:Logger], :error},
    {[:Logger], :flush},
    {[:Logger], :info},
    {[:Logger], :log},
    {[:Logger], :warn},
    {[:Process], :cancel_timer},
    {[:Process], :exit},
    {[:Process], :flag},
    {[:Process], :hibernate},
    {[:Process], :register},
    {[:Process], :sleep},
    {[:Process], :unlink},
    {[:Process], :unregister},
    {[:Registry], :register},
    {[:Registry], :unregister},
    {[:Supervisor], :stop}
  ]

  @block_ops_with_head_expr [:if, :unless, :case, :for, :quote]

  use Credo.Check, base_priority: :high, category: :warning

  def explanations do
    [
      check: @moduledoc,
      params: [
        ignore:
          "A list of function AST names whose return values we should allow ignoring. " <>
            "Elements of the list should look like: {[:Enum], :each} or {[:Custom, :Name, :Here], :function}"
      ]
    ]
  end

  def param_defaults, do: [ignore: []]

  def run(source_file, params \\ []) do
    issue_meta = Credo.IssueMeta.for(source_file, params)
    funs_to_ignore = @funs_to_allow_ignoring ++ Keyword.fetch!(params, :ignore)

    Enum.reduce(find_unused_calls(source_file, params, funs_to_ignore), [], fn invalid_call, issues ->
      {_, meta, _} = invalid_call

      trigger =
        invalid_call
        |> Macro.to_string()
        |> String.split("(")
        |> List.first()

      # credo:disable-for-next-line
      issues ++ [issue_for(&format_issue/2, issue_meta, meta[:line], trigger)]
    end)
  end

  defp issue_for(format_issue_fun, issue_meta, line_no, trigger) do
    format_issue_fun.(
      issue_meta,
      message: "There should be no unused return values.",
      trigger: trigger,
      line_no: line_no
    )
  end

  @def_ops [:def, :defp, :defmacro]
  @block_ops_with_head_expr [:if, :unless, :case, :for, :quote]

  alias Credo.Code.Block
  alias Credo.SourceFile

  def find_unused_calls(%SourceFile{} = source_file, _params, funs_to_allow_ignoring) do
    Credo.Code.prewalk(source_file, &traverse_defs(&1, &2, funs_to_allow_ignoring))
  end

  for op <- @def_ops do
    defp traverse_defs({unquote(op), _meta, arguments} = ast, acc, functions) when is_list(arguments) do
      candidates = Credo.Code.prewalk(ast, &find_candidates(&1, &2, functions))

      if Enum.any?(candidates) do
        {nil, acc ++ filter_unused_calls(ast, candidates)}
      else
        {ast, acc}
      end
    end
  end

  defp traverse_defs(ast, acc, _) do
    {ast, acc}
  end

  #

  defp find_candidates({{:., _, [{:__aliases__, _, modules}, function]}, _, _} = ast, acc, functions) do
    if {modules, function} in functions do
      {ast, acc}
    else
      # credo:disable-for-next-line
      {ast, acc ++ [ast]}
    end
  end

  defp find_candidates(ast, acc, _) do
    {ast, acc}
  end

  # TODO: Everything below this line is unmodified from unused_function_return_helper.ex. If these functions are ever made public, use them.

  defp filter_unused_calls(ast, candidates) do
    candidates
    |> Enum.map(&detect_unused_call(&1, ast))
    |> Enum.reject(&is_nil/1)
  end

  defp detect_unused_call(candidate, ast) do
    ast
    |> Credo.Code.postwalk(&traverse_verify_candidate(&1, &2, candidate), :not_verified)
    |> verified_or_unused_call(candidate)
  end

  defp verified_or_unused_call(:VERIFIED, _), do: nil
  defp verified_or_unused_call(_, candidate), do: candidate

  #

  defp traverse_verify_candidate(ast, acc, candidate) do
    if Credo.Code.contains_child?(ast, candidate) do
      verify_candidate(ast, acc, candidate)
    else
      {ast, acc}
    end
  end

  # we know that `candidate` is part of `ast`

  for op <- @def_ops do
    defp verify_candidate({unquote(op), _, arguments} = ast, :not_verified = _acc, candidate)
         when is_list(arguments) do
      # IO.inspect(ast, label: "#{unquote(op)} (#{Macro.to_string(candidate)} #{acc})")

      if last_call_in_do_block?(ast, candidate) || last_call_in_rescue_block?(ast, candidate) do
        {nil, :VERIFIED}
      else
        {nil, :FALSIFIED}
      end
    end
  end

  defp last_call_in_do_block?(ast, candidate) do
    ast
    |> Block.calls_in_do_block()
    |> List.last()
    |> Credo.Code.contains_child?(candidate)
  end

  defp last_call_in_rescue_block?(ast, candidate) do
    ast
    |> Block.calls_in_rescue_block()
    |> List.last()
    |> Credo.Code.contains_child?(candidate)
  end

  for op <- @block_ops_with_head_expr do
    defp verify_candidate({unquote(op), _, arguments} = ast, :not_verified = acc, candidate)
         when is_list(arguments) do
      # IO.inspect(ast, label: "#{unquote(op)} (#{Macro.to_string(candidate)} #{acc})")

      head_expression = Enum.slice(arguments, 0..-2)

      if Credo.Code.contains_child?(head_expression, candidate) do
        {nil, :VERIFIED}
      else
        {ast, acc}
      end
    end
  end

  defp verify_candidate({:=, _, _} = ast, :not_verified = acc, candidate) do
    # IO.inspect(ast, label: ":= (#{Macro.to_string(candidate)} #{acc})")

    if Credo.Code.contains_child?(ast, candidate) do
      {nil, :VERIFIED}
    else
      {ast, acc}
    end
  end

  defp verify_candidate(
         {:__block__, _, arguments} = ast,
         :not_verified = acc,
         candidate
       )
       when is_list(arguments) do
    # IO.inspect(ast, label: ":__block__ (#{Macro.to_string(candidate)} #{acc})")

    last_call = List.last(arguments)

    if Credo.Code.contains_child?(last_call, candidate) do
      {ast, acc}
    else
      {nil, :FALSIFIED}
    end
  end

  defp verify_candidate(
         {:|>, _, arguments} = ast,
         :not_verified = acc,
         candidate
       ) do
    # IO.inspect(ast, label: ":__block__ (#{Macro.to_string(candidate)} #{acc})")

    last_call = List.last(arguments)

    if Credo.Code.contains_child?(last_call, candidate) do
      {ast, acc}
    else
      {nil, :VERIFIED}
    end
  end

  defp verify_candidate({:->, _, arguments} = ast, :not_verified = acc, _candidate)
       when is_list(arguments) do
    # IO.inspect(ast, label: ":-> (#{Macro.to_string(ast)} #{acc})")

    {ast, acc}
  end

  defp verify_candidate({:fn, _, arguments} = ast, :not_verified = acc, _candidate)
       when is_list(arguments) do
    {ast, acc}
  end

  defp verify_candidate(
         {:try, _, arguments} = ast,
         :not_verified = acc,
         candidate
       )
       when is_list(arguments) do
    # IO.inspect(ast, label: "try (#{Macro.to_string(candidate)} #{acc})")

    after_block = Block.after_block_for!(ast)

    if after_block && Credo.Code.contains_child?(after_block, candidate) do
      {nil, :FALSIFIED}
    else
      {ast, acc}
    end
  end

  # my_fun()
  defp verify_candidate(
         {fun_name, _, arguments} = ast,
         :not_verified = acc,
         candidate
       )
       when is_atom(fun_name) and is_list(arguments) do
    # IO.inspect(ast, label: "my_fun() (#{Macro.to_string(candidate)} #{acc})")

    if Credo.Code.contains_child?(arguments, candidate) do
      {nil, :VERIFIED}
    else
      {ast, acc}
    end
  end

  # module.my_fun()
  defp verify_candidate(
         {{:., _, [{module, _, []}, fun_name]}, _, arguments} = ast,
         :not_verified = acc,
         candidate
       )
       when is_atom(fun_name) and is_atom(module) and is_list(arguments) do
    # IO.inspect(ast, label: "Mod.fun() (#{Macro.to_string(candidate)} #{acc})")

    if Credo.Code.contains_child?(arguments, candidate) do
      {nil, :VERIFIED}
    else
      {ast, acc}
    end
  end

  # :erlang_module.my_fun()
  defp verify_candidate(
         {{:., _, [module, fun_name]}, _, arguments} = ast,
         :not_verified = acc,
         candidate
       )
       when is_atom(fun_name) and is_atom(module) and is_list(arguments) do
    # IO.inspect(ast, label: "Mod.fun() (#{Macro.to_string(candidate)} #{acc})")

    if Credo.Code.contains_child?(arguments, candidate) do
      {nil, :VERIFIED}
    else
      {ast, acc}
    end
  end

  # MyModule.my_fun()
  defp verify_candidate(
         {{:., _, [{:__aliases__, _, mods}, fun_name]}, _, arguments} = ast,
         :not_verified = acc,
         candidate
       )
       when is_atom(fun_name) and is_list(mods) and is_list(arguments) do
    # IO.inspect(ast, label: "Mod.fun() (#{Macro.to_string(candidate)} #{acc})")

    if Credo.Code.contains_child?(arguments, candidate) do
      {nil, :VERIFIED}
    else
      {ast, acc}
    end
  end

  defp verify_candidate(ast, acc, _candidate) do
    # IO.inspect(ast, label: "_ (#{Macro.to_string(candidate)} #{acc})")

    {ast, acc}
  end
end
