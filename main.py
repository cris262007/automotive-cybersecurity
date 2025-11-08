#!/usr/bin/env python3
"""
Automotive Cybersecurity Protection System - Main Daemon
Implements multi-layer defense architecture for vehicle security
"""

import argparse
import logging
import signal
import sys
import time
from pathlib import Path
import yaml

from secure_boot.verify_signatures import BootVerifier
from can_security.can_monitor import CANMonitor
from can_security.ids_system import IntrusionDetectionSystem
from crypto.key_manager import KeyManager
from anomaly_detection.ml_detector import AnomalyDetector
from utils.logger import setup_logger
from utils.alerts import AlertManager

class VehicleSecuritySystem:
    """Main security system orchestrator"""

    def __init__(self, config_path: str):
        """Initialize security system with configuration"""
        self.config = self._load_config(config_path)
        self.logger = setup_logger(
            'VehicleSecuritySystem',
            level=self.config['system']['log_level']
        )

        self.running = False
        self.components = {}

        self.logger.info("Initializing Vehicle Security System...")

    def _load_config(self, config_path: str) -> dict:
        """Load configuration from YAML file"""
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)

    def initialize_components(self):
        """Initialize all security components"""
        try:
            # Initialize Key Manager
            self.logger.info("Initializing Key Manager...")
            self.components['key_manager'] = KeyManager(
                self.config['encryption']
            )

            # Initialize Boot Verifier
            if self.config.get('secure_boot', {}).get('enabled', True):
                self.logger.info("Initializing Boot Verifier...")
                self.components['boot_verifier'] = BootVerifier(
                    self.config.get('secure_boot', {}),
                    self.components['key_manager']
                )

            # Initialize CAN Monitor
            self.logger.info("Initializing CAN Bus Monitor...")
            self.components['can_monitor'] = CANMonitor(
                self.config['can_bus'],
                self.components['key_manager']
            )

            # Initialize IDS
            if self.config['intrusion_detection']['enabled']:
                self.logger.info("Initializing Intrusion Detection System...")
                self.components['ids'] = IntrusionDetectionSystem(
                    self.config['intrusion_detection']
                )

            # Initialize Anomaly Detector
            self.logger.info("Initializing ML Anomaly Detector...")
            self.components['anomaly_detector'] = AnomalyDetector(
                self.config['intrusion_detection']['ml_model']
            )

            # Initialize Alert Manager
            self.logger.info("Initializing Alert Manager...")
            self.components['alert_manager'] = AlertManager(
                self.config['alerts']
            )

            self.logger.info("✅ All components initialized successfully")
            return True

        except Exception as e:
            self.logger.error(f"❌ Failed to initialize components: {e}")
            return False

    def start(self):
        """Start the security system"""
        if not self.initialize_components():
            self.logger.error("Failed to initialize. Exiting...")
            sys.exit(1)

        self.running = True
        self.logger.info("🚗 Vehicle Security System STARTED")

        # Register signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        # Start monitoring
        try:
            self.components['can_monitor'].start()

            # Main monitoring loop
            while self.running:
                self._monitor_cycle()
                time.sleep(0.1)  # 100ms monitoring interval

        except Exception as e:
            self.logger.error(f"Critical error in main loop: {e}")
            self.stop()

    def _monitor_cycle(self):
        """Single monitoring cycle"""
        try:
            # Get CAN bus data
            can_data = self.components['can_monitor'].get_recent_messages()

            if can_data:
                # Run IDS analysis
                if 'ids' in self.components:
                    threats = self.components['ids'].analyze(can_data)
                    if threats:
                        self._handle_threats(threats)

                # Run anomaly detection
                anomalies = self.components['anomaly_detector'].detect(can_data)
                if anomalies:
                    self._handle_anomalies(anomalies)

        except Exception as e:
            self.logger.error(f"Error in monitoring cycle: {e}")

    def _handle_threats(self, threats: list):
        """Handle detected threats"""
        for threat in threats:
            self.logger.warning(f"🚨 THREAT DETECTED: {threat}")
            self.components['alert_manager'].send_alert(
                level='HIGH',
                message=f"IDS detected threat: {threat['type']}",
                details=threat
            )

            # Take defensive action
            if threat['severity'] == 'CRITICAL':
                self.components['can_monitor'].block_message(
                    threat['message_id']
                )

    def _handle_anomalies(self, anomalies: list):
        """Handle detected anomalies"""
        for anomaly in anomalies:
            self.logger.warning(f"⚠️  ANOMALY DETECTED: {anomaly}")
            self.components['alert_manager'].send_alert(
                level='MEDIUM',
                message=f"Anomaly detected: {anomaly['type']}",
                details=anomaly
            )

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}. Shutting down...")
        self.stop()

    def stop(self):
        """Stop the security system"""
        self.logger.info("Stopping Vehicle Security System...")
        self.running = False

        # Stop all components
        for name, component in self.components.items():
            try:
                if hasattr(component, 'stop'):
                    component.stop()
                    self.logger.info(f"Stopped {name}")
            except Exception as e:
                self.logger.error(f"Error stopping {name}: {e}")

        self.logger.info("🛑 Vehicle Security System STOPPED")
        sys.exit(0)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Automotive Cybersecurity Protection System'
    )
    parser.add_argument(
        '--config',
        type=str,
        default='config/security_config.yaml',
        help='Path to configuration file'
    )
    parser.add_argument(
        '--verify-boot',
        action='store_true',
        help='Verify secure boot before starting'
    )

    args = parser.parse_args()

    # Verify configuration exists
    if not Path(args.config).exists():
        print(f"❌ Configuration file not found: {args.config}")
        sys.exit(1)

    # Initialize and start system
    security_system = VehicleSecuritySystem(args.config)
    security_system.start()

if __name__ == '__main__':
    main()
