import logging

class Logger:
    _logger = None

    @classmethod
    def get_logger(cls):
        if cls._logger is None:
            cls._logger = logging.getLogger("Global")
            cls._logger.setLevel(logging.DEBUG)

            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.DEBUG)

            file_handler = logging.FileHandler('log.log')
            file_handler.setLevel(logging.DEBUG)

            formatter = logging.Formatter('%(levelname)s - %(asctime)s.%(msecs)03d - %(module)s:%(funcName)s - %(message)s', "%d %H:%M:%S")
            console_handler.setFormatter(formatter)
            file_handler.setFormatter(formatter)
            cls._logger.addHandler(console_handler)
            cls._logger.addHandler(file_handler)

        return cls._logger

logger = Logger.get_logger()
