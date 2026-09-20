FROM python:3.13-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.13-slim

RUN useradd --no-create-home --shell /usr/sbin/nologin certinspect
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

USER certinspect
ENTRYPOINT ["certinspect"]
CMD ["--help"]
