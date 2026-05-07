import logging
from pythonjsonlogger import jsonlogger
from datetime import datetime

def setup_security_logger():
  logger=logging.getLogger("IgnitionTelemetry")
  logger.setLevel(logging.INFO)

  #prevent duplicate logs
  if not logger.handlers:
    logHandler=logging.FileHandler("ignition_telemtry.log")
    formatter=jsonlogger.JsonFormatter(
      '%(asctime)s %(levelname)s %(message)s %(event_type)s %(source_ip)s %(target_user)s',
      rename_fields={"asctime": "timestamp"}
    )

    logHandler.setFormatter(formatter)
    logger.addHandler(logHandler)

  return logger

#initialize the logger
telemetry=setup_security_logger()

def log_security_event(event_type, message, source_ip="UNKNOWN", target_user="UNKNOWN"):
  """
  Standardized function to fire off a telemetry event.
  """
  telemetry.info(
    message,
    extra={
      "event_type": event_type,
      "Source_ip": source_ip,
      "target_user": target_user
    }
  )
