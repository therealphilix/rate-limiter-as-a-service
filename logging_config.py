"""
logging_config.py
-----------------
Structured logging with structlog.

Why structlog instead of Python's built-in logging?
  Built-in logging produces lines like:
      2024-01-15 12:34:56 INFO     Rate limit check passed for user:42
  That's readable to a human but useless to a machine. You can't query it,
  filter it, or aggregate it without fragile regex. 

  structlog produces:
      {"event": "rate_limit_check", "identifier": "user:42", "allowed": true,
       "remaining": 8, "latency_ms": 1.2, "tenant_id": "abc-123", ...}

  Every field is queryable. In Datadog/Loki/CloudWatch you can instantly
  answer: "which tenant hit their limit most in the last hour?" or
  "what's the p99 latency of /v1/check?" — without writing a parser.

  This is what "observability" means in practice: your logs are data, not prose.

Two output modes:
  - Development (LOG_FORMAT=console): coloured, human-readable, aligned
  - Production  (LOG_FORMAT=json):    one JSON object per line, machine-readable

Set LOG_FORMAT=json in production. Your log aggregator will thank you.
"""

import logging
import sys
import os

import structlog


def setup_logging():
    """
    Call this once at application startup, before any log statements.
    After this, get a logger anywhere with:

        import structlog
        log = structlog.get_logger()
        await log.ainfo("something happened", key="value")

    Or the sync version:
        log.info("something happened", key="value")
    """

    log_level  = os.getenv("LOG_LEVEL", "INFO").upper()
    log_format = os.getenv("LOG_FORMAT", "console")  # "console" | "json"

    # Shared processors run on every log event regardless of output format.
    # They enrich and transform the event dict before it's rendered.
    shared_processors = [
        # Add the log level name ("info", "warning", etc.)
        structlog.stdlib.add_log_level,

        # Add a UTC timestamp in ISO 8601 format
        structlog.processors.TimeStamper(fmt="iso", utc=True),

        # If an exception was passed, render the full traceback as a string
        # so it survives JSON serialization
        structlog.processors.format_exc_info,

        # Render any positional args in the event string (like % formatting)
        structlog.stdlib.PositionalArgumentsFormatter(),

        # Stack info if requested
        structlog.processors.StackInfoRenderer(),
    ]

    if log_format == "json":
        # Production: one compact JSON object per line
        # Compatible with Datadog, Loki, CloudWatch, Splunk, etc.
        renderer = structlog.processors.JSONRenderer()
    else:
        # Development: coloured, human-readable output
        # Shows timestamp | level | event | key=value pairs
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=shared_processors + [
            # Bridge structlog → stdlib so existing libraries that use
            # logging.getLogger() also get structured output
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Configure the stdlib formatter to use structlog's processors
    formatter = structlog.stdlib.ProcessorFormatter(
        processor=renderer,
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(getattr(logging, log_level, logging.INFO))

    # Silence noisy libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Request logging middleware 
# ---------------------------------------------------------------------------

import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Logs every request with method, path, status code, and latency.
    Attach to the FastAPI app once in main.py.

    Produces one log line per request:
      {"event": "http_request", "method": "POST", "path": "/v1/check",
       "status_code": 429, "latency_ms": 2.4}

    The rate limit check endpoint adds its own richer log line on top of
    this — you get the HTTP layer and the business layer separately.
    """

    async def dispatch(self, request: Request, call_next):
        start   = time.perf_counter()
        log     = structlog.get_logger()
        response = await call_next(request)
        latency = round((time.perf_counter() - start) * 1000, 2)

        # Don't log health checks — they're noise at high frequency
        if request.url.path != "/health":
            log.info(
                "http_request",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                latency_ms=latency,
            )

        return response