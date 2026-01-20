with open("ssh_diverse_sample.log", "r") as f:
    data = f.read()

with open("ssh_big_sample.log", "w") as out:
    for _ in range(100):
        out.write(data)
