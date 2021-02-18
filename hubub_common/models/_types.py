
from enum import Enum

class DeviceType(Enum):
    unknown = 'unknown'
    android = 'android'
    ios = 'ios'
    windows = 'windows'
    macos = 'macos'
    linux = 'linux'


DeviceType.unknown.label = "Unknown"
DeviceType.android.label = "Android"
DeviceType.ios.label = "iOS"
DeviceType.windows.label = "Windows"
DeviceType.macos.label = "MacOS"
DeviceType.linux.label = "Linux"


class RegistrationStatus(Enum):
    started = 1
    installed = 2
    inprogress = 3
    expired = 4
    invalid = 5
    completed = 6


class KeysStatus(Enum):
    ok = 1
    invalid = 2