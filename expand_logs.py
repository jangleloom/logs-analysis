with open("ssh_sample.csv", "r") as f:
    data = f.read()

with open("ssh_big_sample.csv", "w") as out:
    for _ in range(100):
        out.write(data)
