import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - WEB_SHIELD_OPS - %(message)s')
logger = logging.getLogger(__name__)

class ResponseManager:
    @staticmethod
    def execute_response(incident_type, source_ip, risk_score):
        actions_taken = []
        if risk_score > 80:
            actions_taken.append(ResponseManager.block_ip_firewall(source_ip))
            actions_taken.append(ResponseManager.notify_soc(incident_type, source_ip))
        elif risk_score > 50:
            actions_taken.append("Flagged for manual review")
        return actions_taken

    @staticmethod
    def block_ip_firewall(ip):
        logger.warning(f"ACTION: [BLOCKING IP] {ip} on Firewall.")
        return f"IP {ip} blocked"

    @staticmethod
    def notify_soc(attack_type, ip):
        logger.info(f"ACTION: [NOTIFICATION] Sent alert to SOC regarding {attack_type} from {ip}.")
        return "SOC Notified"