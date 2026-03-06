#!/usr/bin/env python3
import sys
import argparse
import logging
from app import MainApp
from registry import ModuleRegistry
from logging_config import setup_logging

logger = logging.getLogger(__name__)

def setup_argument_parser():
    """Setup command line argument parser"""
    parser = argparse.ArgumentParser(
        description='Kangaroot - Metasploit-like Terminal Interface for AD ops',
    )
    parser.add_argument('--version', action='version', version=f'%(prog)s v1.0')
    parser.add_argument('--register-modules', action='store_true',
                       help='Register modules from disk and exit')
    parser.add_argument('--list-modules', action='store_true',
                       help='List all registered modules and exit')
    parser.add_argument('--dev', action='store_true',
                       help='Enable dev mode')
    parser.add_argument('--log-level', default='INFO',
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                       help='Set logging level')
    return parser

def register_modules():
    """Register modules from disk"""
    try:
        logger.info("Registering modules from disk")
        registry = ModuleRegistry()
        registry.register_modules_from_disk()
        print("✅ Modules registered successfully")
        registry.close()
        logger.info("Module registration completed")
    except Exception as e:
        logger.error(f"Error registering modules: {e}", exc_info=True)
        print(f"❌ Error registering modules: {e}")
        sys.exit(1)

def list_modules():
    """List all registered modules"""
    try:
        registry = ModuleRegistry()
        modules = registry.get_all_modules()
        
        if not modules:
            print("No modules registered. Run with --register-modules first.")
            return
        
        print(f"📋 Registered Modules ({len(modules)}):")
        print("-" * 60)
        
        # Group by category
        categories = {}
        for module in modules:
            path_parts = module['path'].split('/')
            category = '/'.join(path_parts[:-1]) if len(path_parts) > 1 else 'root'
            if category not in categories:
                categories[category] = []
            categories[category].append(module)
        
        for category in sorted(categories.keys()):
            print(f"\n🗂️  {category}/")
            for module in sorted(categories[category], key=lambda x: x['path']):
                name = module['path'].split('/')[-1]
                print(f"   {name:<20} - {module['description']}")
        
        registry.close()
        
    except Exception as e:
        print(f"❌ Error listing modules: {e}")
        sys.exit(1)

def check_requirements():
    """Check if required dependencies are available"""
    try:
        import textual
    except ImportError:
        print("❌ Textual library not found. Install with: pip install textual")
        sys.exit(1)
    
    # Check Python version
    if sys.version_info < (3, 7):
        print(f"❌ Python 3.7+ required. Current version: {sys.version_info.major}.{sys.version_info.minor}")
        sys.exit(1)

def main():
    """Main entry point"""
    parser = setup_argument_parser()
    args = parser.parse_args()

    # Setup logging
    setup_logging(log_level=args.log_level)
    logger.info("Starting Kangaroot TUI")

    # Check requirements
    check_requirements()

    # Handle special modes
    if args.register_modules:
        register_modules()
        return

    if args.list_modules:
        list_modules()
        return

    # Normal app mode
    try:
        logger.info("Starting main application")
        app = MainApp()
        app.run()
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
        print("\n👋 Goodbye!")
    except Exception as e:
        logger.error(f"Application error: {e}", exc_info=True)
        print(f"❌ Application error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
