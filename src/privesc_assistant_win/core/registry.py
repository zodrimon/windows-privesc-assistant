from typing import Type, Dict
import logging

from privesc_assistant_win.checks.base import BaseCheck


class CheckRegistry:
    """Registry for discovering and instantiating check plugins."""
    
    def __init__(self):
        self._checks: Dict[str, Type[BaseCheck]] = {}
        
    def register(self, check_class: Type[BaseCheck]) -> None:
        """Registers a check class."""
        # Instantiate temporarily just to get the name property
        temp_instance = check_class()
        name = temp_instance.name
        
        if name in self._checks:
            logging.warning(f"Check {name} is already registered. Overwriting.")
            
        self._checks[name] = check_class
        
    def get_check(self, name: str) -> BaseCheck:
        """Instantiates and returns a check by name."""
        if name not in self._checks:
            raise KeyError(f"Check {name} not found in registry.")
        return self._checks[name]()
        
    def get_all_checks(self) -> Dict[str, BaseCheck]:
        """Instantiates and returns all registered checks."""
        return {name: cls() for name, cls in self._checks.items()}


# Global registry instance
registry = CheckRegistry()


def register_check(cls: Type[BaseCheck]) -> Type[BaseCheck]:
    """Decorator for registering a check class."""
    registry.register(cls)
    return cls
