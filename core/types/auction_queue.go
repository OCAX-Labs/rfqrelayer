package types

type AuctionQueue []*OpenRFQ

func (aq AuctionQueue) Len() int {
	return len(aq)
}

func (aq AuctionQueue) Less(i, j int) bool {
	return aq[i].Data.RFQEndTime < aq[j].Data.RFQEndTime
}

func (aq AuctionQueue) Swap(i, j int) {
	aq[i], aq[j] = aq[j], aq[i]
}

func (aq *AuctionQueue) Push(x interface{}) {
	*aq = append(*aq, x.(*OpenRFQ))
}

func (aq *AuctionQueue) Pop() interface{} {
	old := *aq
	n := len(old)
	x := old[n-1]
	*aq = old[0 : n-1]
	return x
}
