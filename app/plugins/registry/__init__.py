
import importlib.util
import os
import sys
from typing import Dict, Any, Type
from app.plugins.base import BasePlugin

class PluginRegistry:
    def __init__(self, plugin_dir: str):
        self.plugin_dir = plugin_dir
        self.loaded_plugins: Dict[str, BasePlugin] = {}

    def load_plugin(self, file_path: str, class_name: str):
        module_name = f'app.plugins.community.{os.path.basename(file_path).replace(".py", "")}'
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)

        plugin_class = getattr(module, class_name)
        instance = plugin_class()
        self.loaded_plugins[instance.plugin_id] = instance
        print(f'[Registry] Loaded: {instance.plugin_id}')

    async def execute_all(self, context: Dict[str, Any]):
        results = {}
        for pid, plugin in self.loaded_plugins.items():
            results[pid] = await plugin.run(context)
        return results
