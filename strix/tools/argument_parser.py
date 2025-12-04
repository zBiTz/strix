import contextlib
import inspect
import json
import types
from collections.abc import Callable
from typing import Any, Union, get_args, get_origin


class ArgumentConversionError(Exception):
    def __init__(self, message: str, param_name: str | None = None) -> None:
        self.param_name = param_name
        super().__init__(message)


def convert_arguments(func: Callable[..., Any], kwargs: dict[str, Any]) -> dict[str, Any]:
    try:
        sig = inspect.signature(func)
        converted = {}

        for param_name, value in kwargs.items():
            if param_name not in sig.parameters:
                converted[param_name] = value
                continue

            param = sig.parameters[param_name]
            param_type = param.annotation

            if param_type == inspect.Parameter.empty or value is None:
                converted[param_name] = value
                continue

            if not isinstance(value, str):
                converted[param_name] = value
                continue

            try:
                converted[param_name] = convert_string_to_type(value, param_type)
            except (ValueError, TypeError, json.JSONDecodeError) as e:
                raise ArgumentConversionError(
                    f"Failed to convert argument '{param_name}' to type {param_type}: {e}",
                    param_name=param_name,
                ) from e

    except (ValueError, TypeError, AttributeError) as e:
        raise ArgumentConversionError(f"Failed to process function arguments: {e}") from e

    return converted


def convert_string_to_type(value: str, param_type: Any) -> Any:
    origin = get_origin(param_type)
    if origin is Union or isinstance(param_type, types.UnionType):
        args = get_args(param_type)
        for arg_type in args:
            if arg_type is not type(None):
                with contextlib.suppress(ValueError, TypeError, json.JSONDecodeError):
                    return convert_string_to_type(value, arg_type)
        return value

    if hasattr(param_type, "__args__"):
        args = getattr(param_type, "__args__", ())
        if len(args) == 2 and type(None) in args:
            non_none_type = args[0] if args[1] is type(None) else args[1]
            with contextlib.suppress(ValueError, TypeError, json.JSONDecodeError):
                return convert_string_to_type(value, non_none_type)
            return value

    return _convert_basic_types(value, param_type, origin)


def _convert_basic_types(value: str, param_type: Any, origin: Any = None) -> Any:
    basic_type_converters: dict[Any, Callable[[str], Any]] = {
        int: int,
        float: float,
        bool: _convert_to_bool,
        str: str,
    }

    if param_type in basic_type_converters:
        return basic_type_converters[param_type](value)

    if list in (origin, param_type):
        return _convert_to_list(value)
    if dict in (origin, param_type):
        return _convert_to_dict(value)

    with contextlib.suppress(json.JSONDecodeError):
        return json.loads(value)
    return value


def _convert_to_bool(value: str) -> bool:
    if value.lower() in ("true", "1", "yes", "on"):
        return True
    if value.lower() in ("false", "0", "no", "off"):
        return False
    return bool(value)


def _convert_to_list(value: str) -> list[Any]:
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return parsed
    except json.JSONDecodeError:
        if "," in value:
            return [item.strip() for item in value.split(",")]
        return [value]
    else:
        return [parsed]


def _convert_to_dict(value: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        return {}
    else:
        return {}


def validate_required_args(
    func: Callable[..., Any], provided_args: dict[str, Any]
) -> tuple[bool, list[str]]:
    """Check if all required parameters are provided.

    Args:
        func: The function to validate arguments for
        provided_args: Dictionary of arguments that were provided

    Returns:
        Tuple of (is_valid, missing_params_list)
        - is_valid: True if all required params are present
        - missing_params_list: List of missing parameter names (empty if all present)
    """
    try:
        sig = inspect.signature(func)
        missing = []

        for param_name, param in sig.parameters.items():
            # Skip special parameters
            if param_name in ("kwargs", "agent_state"):
                continue

            # Check if parameter is required (no default value and not VAR_KEYWORD)
            if (param.default is inspect.Parameter.empty and
                param.kind != inspect.Parameter.VAR_KEYWORD and
                param_name not in provided_args):
                missing.append(param_name)

        return len(missing) == 0, missing

    except (ValueError, TypeError, AttributeError):
        # If we can't introspect, assume valid and let the tool call fail naturally
        return True, []
