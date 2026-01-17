import os
import time
import random

TEST_DIR = "test_files"

def simulate_ransomware():
    print("⚠️ Ransomware simulation started (SAFE MODE)")
    
    if not os.path.exists(TEST_DIR):
        os.makedirs(TEST_DIR)

    files = os.listdir(TEST_DIR)

    if not files:
        # Create dummy files
        for i in range(5):
            with open(f"{TEST_DIR}/file{i}.txt", "w") as f:
                f.write("This is a safe test file\n")
        files = os.listdir(TEST_DIR)

    for _ in range(10):
        target = random.choice(files)
        path = os.path.join(TEST_DIR, target)

        if os.path.isfile(path):
            with open(path, "a") as f:
                f.write("\n⚠️ simulated modification")

            print(f"Modified: {target}")
            time.sleep(1)

    print("✅ Simulation finished")

if __name__ == "__main__":
    simulate_ransomware()
