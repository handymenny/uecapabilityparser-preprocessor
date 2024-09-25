import binascii
import os
import platform
import random
import shutil
import string
import subprocess
import sys
import sysconfig
from pathlib import Path
import importlib.util
import json


def check_dep_installed(name: str) -> bool:
    spec = importlib.util.find_spec(name)
    return spec is not None


def print_stderr(message: str):
    print(f"error: {message}", file=sys.stderr)


def check_python_version(required_version: tuple[int, int]):
    if sys.version_info < required_version:
        print_stderr(
            f"python {required_version[0]}.{required_version[1]} or newer is required"
        )
        sys.exit(1)


def bool_question(question: str) -> bool:
    answer = input(question).lower()
    while True:
        if answer == "y":
            return True
        elif answer == "n":
            return False
        else:
            answer = input("please enter Y or N ")


def is_externally_managed() -> bool:
    if sys.prefix != sys.base_prefix:
        # we're in a venv
        return False
    else:
        syspath = sysconfig.get_path("stdlib", sysconfig.get_default_scheme())
        external_path = os.path.join(syspath, "EXTERNALLY-MANAGED")
        if os.path.exists(external_path):
            return True
    return False


def install_dependency(name: str, package_url: str):
    print(f"trying to install {name}...")
    if is_externally_managed():
        print_stderr(
            f"this environment is externally managed, install {name} manually or run this script in a venv"
        )
        sys.exit(1)
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", package_url, "-q", "-q"]
        )
    except subprocess.CalledProcessError:
        print_stderr(f"can't install {name}. please install it manually")
        sys.exit(1)
    if shutil.which(name):
        print(f"{name} successfully installed")


def get_tshark_path() -> str:
    if shutil.which("tshark"):
        return "tshark"

    tshark_path = None
    if platform.system() == "Windows":
        program_files = [
            os.getenv("ProgramFiles"),
            os.getenv("ProgramFiles(x86)"),
            os.getenv("ProgramW6432"),
        ]

        for path in program_files:
            if path:
                possible_path = os.path.join(path, "Wireshark", "tshark.exe")
                if os.path.exists(possible_path):
                    tshark_path = possible_path
                    break
    return tshark_path


def check_prerequisites():
    check_python_version((3, 7))
    if not shutil.which("scat"):
        res = bool_question(
            "scat isn't installed. should I try to install it automatically? [Y/N] "
        )
        if res:
            install_dependency("scat", "git+https://github.com/fgsect/scat")
        else:
            print("please install it manually")
            sys.exit(1)

    if get_tshark_path() is None:
        print_stderr("tshark not found. please install wireshark/tshark")
        sys.exit(1)

    if not check_dep_installed("json_stream"):
        print(
            "Warning: json_stream isn't installed, it can speedup NSG log parsing. You can install it by running 'pip install json_stream'"
        )


def get_random_string(length: int):
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for _ in range(length))


def convert_log_to_pcap_with_scat(
    input_file: Path, output_file: Path, file_extension: str
):
    sdm = file_extension in [".sdm", ".sdmraw"]
    if sdm:
        arguments = ["-t", "sec"]
    else:
        arguments = ["-t", "qc", "-C", "--cacombos", "--disable-crc-check"]
    subprocess.check_call(
        ["scat", *arguments, "-d", input_file, "-F", output_file],
        stdout=subprocess.DEVNULL,
    )


def convert_nsg_json_to_pcap(input_file: Path, output_file: Path):
    data = None
    with open(input_file, "r") as f:
        if check_dep_installed("json_stream"):
            import json_stream

            data = json_stream.load(f)
        else:
            data = json.load(f)

        if data is None:
            print("error: failed to read json file")

        with open(output_file, "wb") as pcap:
            header = data.get("PCAPHeader")
            if not header:
                print(
                    "error: failed to read PCAPHeader from json file. Likely not a valid NSG json file"
                )
            pcap.write(binascii.unhexlify(header))

            for item in data.get("data", []):
                for message in item.get("messages", []):
                    packet = message.get("PCAPPacket")
                    if packet:
                        pcap.write(binascii.unhexlify(packet))


def optimize_pcap(input_file: Path, output_file: Path):
    tshark_path = get_tshark_path()
    filters = 'lte-rrc.RAT_Type or lte-rrc.rat_Type or nr-rrc.rat_Type or lte-rrc.ulDedicatedMessageSegment_r16_element or nr-rrc.ulDedicatedMessageSegment_r16_element or gsmtap_log.string matches ".*UE CA Combos.*"'
    lua_script = "lua_script:wireshark_plugin/scat.lua"
    subprocess.check_call(
        [
            tshark_path,
            "-X",
            lua_script,
            "-Y",
            filters,
            "-r",
            input_file,
            "-w",
            output_file,
            "-F",
            "pcap",
        ]
    )


def main():
    check_prerequisites()

    if len(sys.argv) >= 2:
        input_file = sys.argv[1]
    else:
        print_stderr("no argument supplied")
        print("usage: python preprocess.py inputfile")
        sys.exit(1)

    input_file_stripped = input_file.strip("'\"")
    input_file_path = Path(input_file_stripped)

    if not input_file_path.exists():
        print(f"error: {input_file} doesn't exist")
        sys.exit(1)

    file_extension = input_file_path.suffix.lower()

    supported_extensions = [
        ".pcap",
        ".pcapng",
        ".hdf",
        ".qmdl",
        ".qmdl2",
        ".dlf",
        ".sdm",
        ".sdmraw",
        ".json",
    ]

    if file_extension not in supported_extensions:
        print(f"error: extension {file_extension} not supported")
        print(
            f"this script supports only the following extensions: {str(supported_extensions)[1:-1]}"
        )
        sys.exit(1)

    path_without_extension = input_file_stripped.removesuffix(file_extension)
    rnd = "-" + get_random_string(4)

    if file_extension in [
        ".hdf",
        ".qmdl",
        ".qmdl2",
        ".dlf",
        ".sdm",
        ".sdmraw",
        ".json",
    ]:
        output_pcap = Path(f"{path_without_extension}{rnd}.pcap")
        print(f"converting {file_extension[1:]} to pcap...")
        if file_extension in [".json"]:
            convert_nsg_json_to_pcap(input_file_path, output_pcap)
        else:
            convert_log_to_pcap_with_scat(input_file_path, output_pcap, file_extension)
        print(f"pcap saved to {output_pcap}")
    else:
        output_pcap = input_file_path

    print("optimizing pcap by removing messages not used by uecapabilityparser...")
    output_pcap_optimized = Path(f"{path_without_extension}{rnd}-optimized.pcap")
    optimize_pcap(output_pcap, output_pcap_optimized)
    print(f"optimized pcap saved to {output_pcap_optimized}")


if __name__ == "__main__":
    main()
