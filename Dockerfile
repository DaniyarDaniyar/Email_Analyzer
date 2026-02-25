FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

# Copy project code
COPY . .

# Install Python dependencies from pyproject.toml
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir .

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

