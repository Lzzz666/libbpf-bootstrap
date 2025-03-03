package udp_nodes

// SeqInfo 定義與 eBPF 程序相同的結構
type SeqInfo struct {
    Sequence  uint32
    Timestamp uint64
}
