import time

import httpx


def test_cluster(setup_cluster, hepcdn_access_header):
    """
    Test the cluster endpoint.
    """
    data = {}
    for _ in range(10):
        for server in setup_cluster:
            response = httpx.get(f"{server}/gossip", headers=hepcdn_access_header)
            data[server] = response.json()

        if all(len(item) == len(setup_cluster) for item in data.values()):
            break
        time.sleep(1)

    assert data
    assert len(data) == len(setup_cluster)
    for server, items in data.items():
        print(server, items)
        assert len(items) == len(setup_cluster)
        for item in items:
            assert item.keys() == {"name", "data"}
            assert item["data"]["status"] == "alive"
            assert item["data"].keys() == {"status", "epoch", "timestamp"}
