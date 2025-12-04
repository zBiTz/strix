from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import queue
import signal
import sys
import threading
from multiprocessing import Process, Queue
from typing import Any, cast

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ValidationError


SANDBOX_MODE = os.getenv("STRIX_SANDBOX_MODE", "false").lower() == "true"
if not SANDBOX_MODE:
    raise RuntimeError("Tool server should only run in sandbox mode (STRIX_SANDBOX_MODE=true)")

# Configurable timeout for tool execution (default: 5 minutes)
try:
    TOOL_EXECUTION_TIMEOUT = int(os.getenv("STRIX_TOOL_TIMEOUT", "300"))
    if TOOL_EXECUTION_TIMEOUT <= 0:
        raise ValueError("Timeout must be positive")  # noqa: TRY301
except ValueError as e:
    raise RuntimeError(
        f"Invalid STRIX_TOOL_TIMEOUT value: {os.getenv('STRIX_TOOL_TIMEOUT')}. "
        f"Must be a positive integer representing seconds. Error: {e}"
    ) from e

parser = argparse.ArgumentParser(description="Start Strix tool server")
parser.add_argument("--token", required=True, help="Authentication token")
parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")  # nosec
parser.add_argument("--port", type=int, required=True, help="Port to bind to")

args = parser.parse_args()
EXPECTED_TOKEN = args.token

app = FastAPI()
security = HTTPBearer()

security_dependency = Depends(security)

agent_processes: dict[str, dict[str, Any]] = {}
agent_queues: dict[str, dict[str, Queue[Any]]] = {}
_agent_lock = threading.Lock()

logger = logging.getLogger(__name__)


def verify_token(credentials: HTTPAuthorizationCredentials) -> str:
    if not credentials or credentials.scheme != "Bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication scheme. Bearer token required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if credentials.credentials != EXPECTED_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return credentials.credentials


class ToolExecutionRequest(BaseModel):
    agent_id: str
    tool_name: str
    kwargs: dict[str, Any]


class ToolExecutionResponse(BaseModel):
    result: Any | None = None
    error: str | None = None


def agent_worker(
    _agent_id: str, request_queue: Queue[Any], response_queue: Queue[Any]
) -> None:
    null_handler = logging.NullHandler()

    root_logger = logging.getLogger()
    root_logger.handlers = [null_handler]
    root_logger.setLevel(logging.CRITICAL)

    from strix.tools.argument_parser import (
        ArgumentConversionError,
        convert_arguments,
        validate_required_args,
    )
    from strix.tools.registry import get_tool_by_name
    from strix.tools.validation import generate_missing_param_error

    while True:
        try:
            request = request_queue.get()

            if request is None:
                break

            tool_name = request.get("tool_name", "unknown")
            kwargs = request.get("kwargs", {})

            try:
                tool_func = get_tool_by_name(tool_name)
                if not tool_func:
                    response_queue.put({"error": f"Tool '{tool_name}' not found"})
                    continue

                converted_kwargs = convert_arguments(tool_func, kwargs)

                # Pre-validate that all required parameters are present
                is_valid, missing_params = validate_required_args(tool_func, converted_kwargs)
                if not is_valid:
                    # Return helpful error message for missing parameters
                    error_dict = generate_missing_param_error(
                        tool_name, missing_params, converted_kwargs
                    )
                    response_queue.put({"error": error_dict})
                    continue

                result = tool_func(**converted_kwargs)

                response_queue.put({"result": result})

            except TypeError as e:
                # Handle missing required parameters that somehow slipped through
                error_str = str(e)
                if "missing" in error_str and "required" in error_str:
                    import re

                    match = re.search(r"'(\w+)'", error_str)
                    param_name = match.group(1) if match else "unknown"
                    error_dict = generate_missing_param_error(tool_name, [param_name], kwargs)
                    error_dict["original_error"] = error_str
                    response_queue.put({"error": error_dict})
                else:
                    response_queue.put({"error": f"Type error: {e}"})
            except (ArgumentConversionError, ValidationError) as e:
                response_queue.put({"error": f"Invalid arguments: {e}"})
            except (RuntimeError, ValueError, ImportError) as e:
                response_queue.put({"error": f"Tool execution error: {e}"})
            except Exception as e:  # noqa: BLE001
                # Catch ALL exceptions to ensure response is always sent
                response_queue.put({"error": f"Unexpected error executing {tool_name}: {e!s}"})

        except Exception as e:  # noqa: BLE001
            # Even if getting request from queue fails, try to send an error response
            # Use contextlib.suppress for cleaner exception handling
            with contextlib.suppress(Exception):
                response_queue.put({"error": f"Worker error: {e!s}"})


def cleanup_agent(agent_id: str) -> None:
    """Clean up a single agent's process and queues."""
    with _agent_lock:
        if agent_id in agent_processes:
            try:
                process = agent_processes[agent_id]["process"]
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=1)
                    if process.is_alive():
                        process.kill()
            except (BrokenPipeError, EOFError, OSError) as e:
                logger.debug(f"Error during agent {agent_id} cleanup: {e}")
            finally:
                agent_processes.pop(agent_id, None)
                agent_queues.pop(agent_id, None)


def ensure_agent_process(agent_id: str) -> tuple[Queue[Any], Queue[Any]]:
    with _agent_lock:
        if agent_id not in agent_processes:
            request_queue: Queue[Any] = Queue()
            response_queue: Queue[Any] = Queue()

            process = Process(
                target=agent_worker, args=(agent_id, request_queue, response_queue), daemon=True
            )
            process.start()

            agent_processes[agent_id] = {"process": process, "pid": process.pid}
            agent_queues[agent_id] = {"request": request_queue, "response": response_queue}

        return agent_queues[agent_id]["request"], agent_queues[agent_id]["response"]


@app.post("/execute", response_model=ToolExecutionResponse)
async def execute_tool(
    request: ToolExecutionRequest, credentials: HTTPAuthorizationCredentials = security_dependency
) -> ToolExecutionResponse:
    verify_token(credentials)

    # Get or create agent process
    try:
        request_queue, response_queue = ensure_agent_process(request.agent_id)

        # After getting queues, check if process is still alive
        process_info = agent_processes.get(request.agent_id)
        if process_info:
            process = process_info.get("process")
            if process and not process.is_alive():
                # Worker died after being created, recreate
                cleanup_agent(request.agent_id)
                request_queue, response_queue = ensure_agent_process(request.agent_id)
    except (RuntimeError, ValueError, OSError) as e:
        return ToolExecutionResponse(error=f"Failed to ensure worker process: {e}")

    request_queue.put({"tool_name": request.tool_name, "kwargs": request.kwargs})

    try:
        loop = asyncio.get_event_loop()

        # Use a timeout wrapper for the blocking queue.get()
        def get_with_timeout() -> dict[str, Any]:
            try:
                return cast("dict[str, Any]", response_queue.get(timeout=TOOL_EXECUTION_TIMEOUT))
            except queue.Empty:
                return {"error": f"Tool execution timed out after {TOOL_EXECUTION_TIMEOUT} seconds"}

        response = await loop.run_in_executor(None, get_with_timeout)

        if "error" in response:
            # Handle both string errors and dict errors
            error_value = response["error"]
            if isinstance(error_value, dict):
                # Return structured error directly
                return ToolExecutionResponse(error=error_value, result=None)
            else:
                return ToolExecutionResponse(error=str(error_value), result=None)
        return ToolExecutionResponse(result=response.get("result"))

    except (RuntimeError, ValueError, OSError) as e:
        return ToolExecutionResponse(error=f"Worker error: {e}")


@app.post("/register_agent")
async def register_agent(
    agent_id: str, credentials: HTTPAuthorizationCredentials = security_dependency
) -> dict[str, str]:
    verify_token(credentials)

    ensure_agent_process(agent_id)
    return {"status": "registered", "agent_id": agent_id}


@app.get("/health")
async def health_check() -> dict[str, Any]:
    return {
        "status": "healthy",
        "sandbox_mode": str(SANDBOX_MODE),
        "environment": "sandbox" if SANDBOX_MODE else "main",
        "auth_configured": "true" if EXPECTED_TOKEN else "false",
        "active_agents": len(agent_processes),
        "agents": list(agent_processes.keys()),
    }


def cleanup_all_agents() -> None:
    for agent_id in list(agent_processes.keys()):
        try:
            agent_queues[agent_id]["request"].put(None)
            process = agent_processes[agent_id]["process"]

            process.join(timeout=1)

            if process.is_alive():
                process.terminate()
                process.join(timeout=1)

            if process.is_alive():
                process.kill()

        except (BrokenPipeError, EOFError, OSError):
            pass
        except (RuntimeError, ValueError) as e:
            logging.getLogger(__name__).debug(f"Error during agent cleanup: {e}")


def signal_handler(_signum: int, _frame: Any) -> None:
    signal.signal(signal.SIGPIPE, signal.SIG_IGN) if hasattr(signal, "SIGPIPE") else None
    cleanup_all_agents()
    sys.exit(0)


if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    try:
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    finally:
        cleanup_all_agents()
