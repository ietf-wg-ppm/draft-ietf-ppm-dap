TARGETS_DRAFTS := draft-gpew-priv-ppm
TARGETS_TAGS := 
draft-gpew-priv-ppm-00.md: draft-gpew-priv-ppm.md
	sed -e 's/draft-gpew-priv-ppm-latest/draft-gpew-priv-ppm-00/g' $< >$@
