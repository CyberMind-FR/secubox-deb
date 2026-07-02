# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
Tests pour le module DHT (Distributed Hash Table).
Spec: Issue P2P-EVO-2026-07-001
"""
import asyncio
import hashlib
import json
import random
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from secubox.p2p.api.dht import (
    DHTNode, DHTBucket, DHTNetwork,
    KAD_B, PEER_TIMEOUT, DHT_PORT
)


class TestDHTNode:
    """Tests pour DHTNode."""
    
    def test_node_creation(self):
        """Test creation of a DHTNode."""
        node = DHTNode(
            node_id="a" * 40,  # 20-byte hex string
            ip="192.168.1.1",
            port=6881
        )
        
        assert node.node_id == "a" * 40
        assert node.ip == "192.168.1.1"
        assert node.port == 6881
        assert isinstance(node.last_seen, float)
    
    def test_node_expiration(self):
        """Test node expiration logic."""
        # Create a node with old timestamp
        node = DHTNode(
            node_id="b" * 40,
            ip="192.168.1.2",
            port=6882,
            last_seen=time.time() - PEER_TIMEOUT - 1  # Expired
        )
        
        assert node.is_expired()
        
        # Create a node with recent timestamp
        node = DHTNode(
            node_id="c" * 40,
            ip="192.168.1.3",
            port=6883,
            last_seen=time.time()  # Recent
        )
        
        assert not node.is_expired()
    
    def test_node_serialization(self):
        """Test node serialization and deserialization."""
        node = DHTNode(
            node_id="d" * 40,
            ip="192.168.1.4",
            port=6884,
            last_seen=time.time()
        )
        
        data = node.to_dict()
        restored = DHTNode.from_dict(data)
        
        assert restored.node_id == node.node_id
        assert restored.ip == node.ip
        assert restored.port == node.port
        assert abs(restored.last_seen - node.last_seen) < 0.1


class TestDHTBucket:
    """Tests pour DHTBucket."""
    
    def test_bucket_add_node(self):
        """Test adding nodes to a bucket."""
        bucket = DHTBucket()
        
        # Add first node
        node1 = DHTNode(node_id="1" * 40, ip="192.168.1.1", port=6881)
        assert bucket.add_node(node1) is True
        assert len(bucket.nodes) == 1
        
        # Add different node
        node2 = DHTNode(node_id="2" * 40, ip="192.168.1.2", port=6882)
        assert bucket.add_node(node2) is True
        assert len(bucket.nodes) == 2
    
    def test_bucket_duplicate_node(self):
        """Test adding duplicate node to bucket."""
        bucket = DHTBucket()
        
        node = DHTNode(node_id="1" * 40, ip="192.168.1.1", port=6881)
        assert bucket.add_node(node) is True
        
        # Add same node again
        node_dup = DHTNode(node_id="1" * 40, ip="192.168.1.1", port=6881)
        assert bucket.add_node(node_dup) is False  # Returns False for existing
        assert len(bucket.nodes) == 1
    
    def test_bucket_full(self):
        """Test bucket capacity limit."""
        bucket = DHTBucket()
        
        # Fill bucket to capacity
        for i in range(KAD_B):
            node = DHTNode(node_id=str(i) * 40, ip=f"192.168.1.{i}", port=6881 + i)
            assert bucket.add_node(node) is True
        
        assert len(bucket.nodes) == KAD_B
        
        # Try to add one more
        node_extra = DHTNode(node_id="X" * 40, ip="192.168.1.100", port=6890)
        assert bucket.add_node(node_extra) is False
        assert len(bucket.nodes) == KAD_B
    
    def test_bucket_get_nodes(self):
        """Test getting nodes from bucket."""
        bucket = DHTBucket()
        
        # Add some nodes
        node1 = DHTNode(node_id="1" * 40, ip="192.168.1.1", port=6881)
        node2 = DHTNode(node_id="2" * 40, ip="192.168.1.2", port=6882)
        node3 = DHTNode(node_id="3" * 40, ip="192.168.1.3", port=6883)
        
        bucket.add_node(node1)
        bucket.add_node(node2)
        bucket.add_node(node3)
        
        # Get all nodes
        nodes = bucket.get_nodes()
        assert len(nodes) == 3
        
        # Get nodes excluding one
        nodes_no_2 = bucket.get_nodes(exclude_id="2" * 40)
        assert len(nodes_no_2) == 2
        assert all(n.node_id != "2" * 40 for n in nodes_no_2)
    
    def test_bucket_remove_expired(self):
        """Test removing expired nodes from bucket."""
        bucket = DHTBucket()
        
        # Add recent and expired nodes
        recent_node = DHTNode(node_id="1" * 40, ip="192.168.1.1", port=6881)
        expired_node = DHTNode(
            node_id="2" * 40, 
            ip="192.168.1.2", 
            port=6882,
            last_seen=time.time() - PEER_TIMEOUT - 1
        )
        
        bucket.add_node(recent_node)
        bucket.add_node(expired_node)
        
        assert len(bucket.nodes) == 2
        
        # Remove expired
        removed = bucket.remove_expired()
        assert removed == 1
        assert len(bucket.nodes) == 1
        assert bucket.nodes[0].node_id == "1" * 40


class TestDHTNetwork:
    """Tests pour DHTNetwork."""
    
    @pytest.fixture
    def dht_network(self):
        """Create a DHTNetwork instance for testing."""
        dht = DHTNetwork(node_id="local" * 20, ip="127.0.0.1", port=6885)
        return dht
    
    def test_network_creation(self, dht_network):
        """Test DHT network creation."""
        assert dht_network.node_id == "local" * 20
        assert dht_network.ip == "127.0.0.1"
        assert dht_network.port == 6885
        assert len(dht_network.buckets) == 160
    
    def test_node_id_generation(self):
        """Test automatic node ID generation."""
        dht1 = DHTNetwork()
        dht2 = DHTNetwork()
        
        assert len(dht1.node_id) == 40  # SHA-1 hex is 40 chars
        assert len(dht2.node_id) == 40
        assert dht1.node_id != dht2.node_id  # Should be unique
    
    def test_bucket_index_calculation(self, dht_network):
        """Test bucket index calculation."""
        # Same node ID should give same bucket
        idx1 = dht_network._get_bucket_index("a" * 40)
        idx2 = dht_network._get_bucket_index("a" * 40)
        assert idx1 == idx2
        
        # Different node IDs may give different buckets
        idx3 = dht_network._get_bucket_index("b" * 40)
        # Note: idx3 might equal idx1 due to XOR distance
    
    def test_bootstrap_node_addition(self, dht_network):
        """Test adding bootstrap nodes."""
        dht_network.add_bootstrap_node("192.168.1.1", 6881)
        dht_network.add_bootstrap_node("192.168.1.2", 6882)
        
        assert len(dht_network.bootstrap_nodes) == 2
        assert ("192.168.1.1", 6881) in dht_network.bootstrap_nodes
    
    def test_announce_peer(self, dht_network):
        """Test announcing a peer."""
        result = asyncio.run(dht_network.announce_peer(
            node_id="peer" * 20,
            ip="192.168.1.10",
            port=6881
        ))
        
        assert result is True
        assert "peer" * 20 in dht_network.known_peers
        
        peer = dht_network.known_peers["peer" * 20]
        assert peer.ip == "192.168.1.10"
        assert peer.port == 6881
    
    def test_find_peers(self, dht_network):
        """Test finding peers."""
        # Add some peers
        asyncio.run(dht_network.announce_peer("peer1" * 20, "192.168.1.10", 6881))
        asyncio.run(dht_network.announce_peer("peer2" * 20, "192.168.1.11", 6882))
        asyncio.run(dht_network.announce_peer("peer3" * 20, "192.168.1.12", 6883))
        
        # Find all peers
        peers = asyncio.run(dht_network.find_peers())
        assert len(peers) == 3
        
        # Find limited peers
        limited_peers = asyncio.run(dht_network.find_peers(limit=2))
        assert len(limited_peers) == 2
    
    def test_store_and_get_value(self, dht_network):
        """Test storing and retrieving values."""
        # Store a value
        asyncio.run(dht_network.store_value("test_key", "test_value", ttl=3600))
        
        # Retrieve the value
        value = asyncio.run(dht_network.get_value("test_key"))
        assert value == "test_value"
        
        # Get non-existent value
        none_value = asyncio.run(dht_network.get_value("nonexistent"))
        assert none_value is None
    
    def test_value_expiration(self, dht_network):
        """Test value expiration."""
        # Store a value with very short TTL
        asyncio.run(dht_network.store_value("short_ttl", "value", ttl=1))
        
        # Should be available immediately
        value = asyncio.run(dht_network.get_value("short_ttl"))
        assert value == "value"
        
        # Wait for expiration
        time.sleep(1.1)
        
        # Should be expired now
        value = asyncio.run(dht_network.get_value("short_ttl"))
        assert value is None
    
    def test_stats(self, dht_network):
        """Test getting DHT statistics."""
        asyncio.run(dht_network.announce_peer("peer1" * 20, "192.168.1.10", 6881))
        asyncio.run(dht_network.announce_peer("peer2" * 20, "192.168.1.11", 6882))
        asyncio.run(dht_network.store_value("key1", "value1"))
        
        stats = asyncio.run(dht_network.get_stats())
        
        assert "node_id" in stats
        assert "total_peers" in stats
        assert "known_peers" in stats
        assert "store_size" in stats
        assert stats["known_peers"] == 2
        assert stats["store_size"] == 1


class TestBencode:
    """Tests pour l'encodage/décodage bencode."""
    
    def test_bencode_string(self):
        """Test bencoding strings."""
        dht = DHTNetwork()
        
        # Test string
        encoded = dht._bencode("hello")
        assert encoded == b"5:hello"
        
        # Test empty string
        encoded = dht._bencode("")
        assert encoded == b"0:"
    
    def test_bencode_integer(self):
        """Test bencoding integers."""
        dht = DHTNetwork()
        
        encoded = dht._bencode(42)
        assert encoded == b"i42e"
        
        encoded = dht._bencode(0)
        assert encoded == b"i0e"
        
        encoded = dht._bencode(-10)
        assert encoded == b"i-10e"
    
    def test_bencode_list(self):
        """Test bencoding lists."""
        dht = DHTNetwork()
        
        encoded = dht._bencode(["hello", "world"])
        assert encoded == b"l5:hello5:worlde"
        
        encoded = dht._bencode([1, 2, 3])
        assert encoded == b"li1ei2ei3ee"
    
    def test_bencode_dict(self):
        """Test bencoding dictionaries."""
        dht = DHTNetwork()
        
        encoded = dht._bencode({"key": "value"})
        assert encoded == b"d3:key5:valuee"
        
        encoded = dht._bencode({"a": 1, "b": 2})
        # Keys are sorted alphabetically
        assert encoded == b"d1:ai1e1:bi2ee"
    
    def test_bdecode_string(self):
        """Test bdecoding strings."""
        dht = DHTNetwork()
        
        decoded = dht._bdecode(b"5:hello")
        assert decoded == "hello"
        
        decoded = dht._bdecode(b"0:")
        assert decoded == ""
    
    def test_bdecode_integer(self):
        """Test bdecoding integers."""
        dht = DHTNetwork()
        
        decoded = dht._bdecode(b"i42e")
        assert decoded == 42
        
        decoded = dht._bdecode(b"i0e")
        assert decoded == 0
    
    def test_bdecode_list(self):
        """Test bdecoding lists."""
        dht = DHTNetwork()
        
        decoded = dht._bdecode(b"l5:hello5:worlde")
        assert decoded == ["hello", "world"]
    
    def test_bdecode_dict(self):
        """Test bdecoding dictionaries."""
        dht = DHTNetwork()
        
        decoded = dht._bdecode(b"d3:key5:valuee")
        assert decoded == {"key": "value"}


class TestKademliaAlgorithm:
    """Tests pour l'algorithme Kademlia."""
    
    def test_xor_distance(self):
        """Test XOR distance calculation."""
        dht = DHTNetwork(node_id="a" * 40)
        
        # Calculate bucket index for different node IDs
        idx_same = dht._get_bucket_index("a" * 40)
        assert idx_same == 0  # Same ID should be in bucket 0
        
        # Different IDs should be in different buckets
        idx_diff1 = dht._get_bucket_index("b" * 40)
        idx_diff2 = dht._get_bucket_index("c" * 40)
        
        # They might be the same or different depending on XOR result
        # But they should be between 0 and 159
        assert 0 <= idx_diff1 <= 159
        assert 0 <= idx_diff2 <= 159
    
    def test_find_closest_nodes(self):
        """Test finding closest nodes."""
        dht = DHTNetwork(node_id="a" * 40)
        
        # Add some nodes to different buckets
        for i in range(10):
            node = DHTNode(node_id=str(i) * 40, ip=f"192.168.1.{i}", port=6881 + i)
            bucket_idx = dht._get_bucket_index(node.node_id)
            dht.buckets[bucket_idx].add_node(node)
        
        # Find closest nodes to a target
        closest = asyncio.run(dht._find_closest_nodes("a" * 40))
        
        # Should return up to KAD_B nodes
        assert len(closest) <= KAD_B
        
        # The local node (a...a) should be closest to itself
        # But since we didn't add it, we get other nodes


class TestDHTIntegration:
    """Tests d'intégration pour la DHT."""
    
    @pytest.mark.asyncio
    async def test_peer_discovery_workflow(self):
        """Test complete peer discovery workflow."""
        # Create DHT network
        dht = DHTNetwork(node_id="local" * 20, ip="127.0.0.1", port=6885)
        
        # Add bootstrap node
        dht.add_bootstrap_node("127.0.0.1", 6886)
        
        # Announce some peers
        await dht.announce_peer("peer1" * 20, "192.168.1.10", 6881)
        await dht.announce_peer("peer2" * 20, "192.168.1.11", 6882)
        await dht.announce_peer("peer3" * 20, "192.168.1.12", 6883)
        
        # Find peers
        peers = await dht.find_peers()
        assert len(peers) == 3
        
        # Store and retrieve service info
        await dht.store_value("service:api:peer1" * 20, {"endpoint": "http://192.168.1.10:8080"})
        
        service_info = await dht.get_value("service:api:peer1" * 20)
        assert service_info["endpoint"] == "http://192.168.1.10:8080"
        
        # Get stats
        stats = await dht.get_stats()
        assert stats["known_peers"] == 3
        assert stats["store_size"] == 1
