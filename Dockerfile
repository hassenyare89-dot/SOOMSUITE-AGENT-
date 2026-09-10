FROM python:3.13-slim AS runtime
RUN useradd --create-home --uid 10001 app
WORKDIR /app
COPY pyproject.toml ./
RUN pip install --no-cache-dir .
COPY apps/api ./apps/api
USER 10001
ENV PYTHONPATH=/app/apps/api
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]
