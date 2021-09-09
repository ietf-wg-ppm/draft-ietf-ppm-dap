TARGETS_DRAFTS := draft-ppm-protocol
TARGETS_TAGS := 
draft-ppm-protocol-00.md: draft-ppm-protocol.md
	sed -e 's/draft-ppm-protocol-latest/draft-ppm-protocol-00/g' $< >$@
