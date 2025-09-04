from injectpy import ProcessUtils

if __name__ == "__main__":
    process_name = "ProcessName.exe"
    pids = ProcessUtils.get_pids_by_name(process_name)

    if not pids:
        print(f"No processes found with the name '{process_name}'.")
    else:
        print(f"Found {len(pids)} process(es) named '{process_name}':")
        for index, pid in enumerate(pids):
            print(f"Index: {index}, PID: {pid}")