from alembic import context
from sqlalchemy import engine_from_config,pool
config=context.config
def run_migrations_offline():
 context.configure(url=config.get_main_option("sqlalchemy.url"),literal_binds=True); context.run_migrations()
def run_migrations_online():
 with engine_from_config(config.get_section(config.config_ini_section),prefix="sqlalchemy.",poolclass=pool.NullPool).connect() as connection:
  context.configure(connection=connection); context.run_migrations()
run_migrations_offline() if context.is_offline_mode() else run_migrations_online()
