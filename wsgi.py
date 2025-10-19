# wsgi.py
import importlib.util
import sys
import os

# Explicitly load app.py as a standalone module
spec = importlib.util.spec_from_file_location("app_module", os.path.join(os.path.dirname(__file__), "app.py"))
app_module = importlib.util.module_from_spec(spec)
sys.modules["app_module"] = app_module
spec.loader.exec_module(app_module)

# Create the Flask production app
app = app_module.create_production_app()
