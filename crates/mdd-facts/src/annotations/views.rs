use super::*;

impl AnnotationFacts {
    /// Resolve a physically validated collection start in this exact occurrence.
    /// Limits bound the selected kind's physical item count and selected slot
    /// count, not bytes scanned, CPU, allocation or RSS. Empty and orphan
    /// physical collections remain valid; `None` slots are preserved.
    pub fn collection_by_ref(
        &self,
        reference: &AnnotationCollectionRef,
        max_physical_items: u64,
        max_slots: u64,
    ) -> MddResult<AnnotationCollectionView<'_>> {
        let source = self.source();
        if reference.snapshot_id != source.snapshot_id
            || reference.dex_occurrence_id != source.dex_occurrence_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.annotation_collections",
                "collection belongs to another snapshot or occurrence",
            ));
        }
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.annotation_collections",
                "complete metadata, definitions and annotations are required",
            ));
        }
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.annotation_collections",
                "collection entry budget exceeded",
            )
        };
        let invalid = || {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.annotation_collections",
                "collection offset is not a physical item start",
            )
        };
        let broken = || {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.annotation_collections",
                "validated collection is inconsistent",
            )
        };
        let raw = |offset: u32, length: u64, start: u64| -> MddResult<&[u8]> {
            if start != u64::from(offset) {
                return Err(broken());
            }
            let end = start.checked_add(length).ok_or_else(broken)?;
            let begin = usize::try_from(start).map_err(|_| broken())?;
            let end = usize::try_from(end).map_err(|_| broken())?;
            self.bytes().get(begin..end).ok_or_else(broken)
        };
        match reference.kind {
            AnnotationCollectionKind::Set => {
                if u64::try_from(self.data.sets.len()).map_err(|_| quota())? > max_physical_items {
                    return Err(quota());
                }
                let mut found = self
                    .data
                    .sets
                    .iter()
                    .filter(|v| v.byte_offset == reference.byte_offset);
                let item = found.next().ok_or_else(invalid)?;
                if found.next().is_some() {
                    return Err(broken());
                }
                if u64::try_from(item.annotation_offsets.len()).map_err(|_| quota())? > max_slots {
                    return Err(quota());
                }
                let raw_encoded = raw(
                    item.byte_offset,
                    item.encoded_range.byte_length.0,
                    item.encoded_range.byte_offset.0,
                )?;
                Ok(AnnotationCollectionView::Set {
                    source,
                    item,
                    raw_encoded,
                })
            }
            AnnotationCollectionKind::SetRefList => {
                if u64::try_from(self.data.ref_lists.len()).map_err(|_| quota())?
                    > max_physical_items
                {
                    return Err(quota());
                }
                let mut found = self
                    .data
                    .ref_lists
                    .iter()
                    .filter(|v| v.byte_offset == reference.byte_offset);
                let item = found.next().ok_or_else(invalid)?;
                if found.next().is_some() {
                    return Err(broken());
                }
                if u64::try_from(item.annotation_set_offsets.len()).map_err(|_| quota())?
                    > max_slots
                {
                    return Err(quota());
                }
                let raw_encoded = raw(
                    item.byte_offset,
                    item.encoded_range.byte_length.0,
                    item.encoded_range.byte_offset.0,
                )?;
                Ok(AnnotationCollectionView::SetRefList {
                    source,
                    item,
                    raw_encoded,
                })
            }
        }
    }
    /// Resolve a single encoded owner binding to its physical annotation items.
    /// `parameter_slot` selects an encoded method-parameter slot; `None` selects
    /// class, field, or method annotations themselves. For a parameter slot,
    /// consult `owner.parameter_position_in_prototype` before interpreting it as
    /// a prototype position. `None` means no matching encoded owner binding in
    /// this occurrence; use `method_encoded_parameter_list` when a caller must
    /// distinguish an absent list from a present list without that slot.
    ///
    /// The limits cover logical scans and returned entries, not allocation
    /// overhead, CPU time or RSS. Empty sets and explicit zero slots remain
    /// distinct, and repeated physical entries are never deduplicated.
    pub fn owner_annotation_facts(
        &self,
        owner: &EntityRef,
        parameter_slot: Option<u32>,
        limits: AnnotationOwnerViewLimits,
    ) -> MddResult<Option<OwnerAnnotationFacts<'_>>> {
        let source = self.source();
        if owner.snapshot_id != source.snapshot_id
            || owner.dex_occurrence_id != source.dex_occurrence_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.owner_annotations",
                "owner belongs to another snapshot or occurrence",
            ));
        }
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.owner_annotations",
                "complete metadata, definitions and annotations are required",
            ));
        }
        let definitions = self.definitions.definitions();
        let (kind, definition_scan) = match (owner.kind, parameter_slot) {
            (EntityKind::ClassDefinition, None) => (AnnotationOwnerKind::Class, 0),
            (EntityKind::FieldReference, None) => (AnnotationOwnerKind::Field, 0),
            (EntityKind::FieldDefinition, None) => (
                AnnotationOwnerKind::Field,
                definitions.field_definitions.len(),
            ),
            (EntityKind::MethodReference, None) => (AnnotationOwnerKind::Method, 0),
            (EntityKind::MethodDefinition, None) => (
                AnnotationOwnerKind::Method,
                definitions.method_definitions.len(),
            ),
            (EntityKind::MethodReference, Some(_)) => (AnnotationOwnerKind::Parameter, 0),
            (EntityKind::MethodDefinition, Some(_)) => (
                AnnotationOwnerKind::Parameter,
                definitions.method_definitions.len(),
            ),
            _ => {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.owner_annotations",
                    "owner kind and parameter slot are incompatible",
                ));
            }
        };
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.owner_annotations",
                "owner annotation view budget exceeded",
            )
        };
        let broken = || {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.owner_annotations",
                "validated owner annotation facts are inconsistent",
            )
        };
        let in_captured_bytes = |offset: u64, length: u64| -> bool {
            let Some(end) = offset.checked_add(length) else {
                return false;
            };
            let (Ok(start), Ok(end)) = (usize::try_from(offset), usize::try_from(end)) else {
                return false;
            };
            self.bytes().get(start..end).is_some()
        };
        let mut visits = u64::try_from(definition_scan).map_err(|_| quota())?;
        if visits > limits.max_scanned_entries {
            return Err(quota());
        }
        self.definitions.entity(owner.kind, owner.local_index)?;
        let mut tick = || -> MddResult<()> {
            visits = visits.checked_add(1).ok_or_else(quota)?;
            if visits > limits.max_scanned_entries {
                return Err(quota());
            }
            Ok(())
        };
        let mut binding = None;
        for candidate in &self.data.owner_bindings {
            tick()?;
            if candidate.kind == kind
                && candidate.local_index == owner.local_index
                && candidate.parameter_ordinal == parameter_slot
                && binding.replace(candidate).is_some()
            {
                return Err(broken());
            }
        }
        let Some(binding) = binding else {
            return Ok(None);
        };
        let Some(offset) = binding.annotation_set_offset else {
            if kind != AnnotationOwnerKind::Parameter {
                return Err(broken());
            }
            return Ok(Some(OwnerAnnotationFacts {
                source,
                owner: binding,
                set: None,
                annotations: Vec::new(),
            }));
        };
        let mut selected = None;
        for set in &self.data.sets {
            tick()?;
            if set.byte_offset == offset && selected.replace(set).is_some() {
                return Err(broken());
            }
        }
        let set = selected.ok_or_else(broken)?;
        if set.encoded_range.byte_offset.0 != u64::from(offset)
            || !in_captured_bytes(
                set.encoded_range.byte_offset.0,
                set.encoded_range.byte_length.0,
            )
        {
            return Err(broken());
        }
        let mut annotations = Vec::new();
        for (ordinal, offset) in set.annotation_offsets.iter().enumerate() {
            tick()?;
            let mut item = None;
            for candidate in &self.data.annotation_items {
                tick()?;
                if candidate.byte_offset == *offset && item.replace(candidate).is_some() {
                    return Err(broken());
                }
            }
            let item = item.ok_or_else(broken)?;
            if item.encoded_range.byte_offset.0 != u64::from(*offset)
                || !in_captured_bytes(
                    item.encoded_range.byte_offset.0,
                    item.encoded_range.byte_length.0,
                )
            {
                return Err(broken());
            }
            if u64::try_from(annotations.len()).map_err(|_| quota())? >= limits.max_matches {
                return Err(quota());
            }
            annotations.try_reserve(1).map_err(|_| quota())?;
            annotations.push(AnnotationOwnerFact {
                source,
                owner: binding,
                set,
                annotation: item,
                set_ordinal: u32::try_from(ordinal).map_err(|_| quota())?,
            });
        }
        Ok(Some(OwnerAnnotationFacts {
            source,
            owner: binding,
            set: Some(set),
            annotations,
        }))
    }

    /// Reverse lookup of one validated physical item across encoded owners in
    /// this DEX occurrence. An empty result proves only that this item has no
    /// encoded owner in these complete facts, not absence from other inputs.
    /// Orphan items and empty sets remain valid. Shared sets yield one result
    /// per owner and per encoded item occurrence; no semantic inheritance or
    /// prototype-position completeness is inferred.
    pub fn annotation_owner_facts(
        &self,
        annotation: &AnnotationRef,
        limits: AnnotationOwnerViewLimits,
    ) -> MddResult<Vec<AnnotationOwnerFact<'_>>> {
        let source = self.source();
        if annotation.snapshot_id != source.snapshot_id
            || annotation.dex_occurrence_id != source.dex_occurrence_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.annotation_owners",
                "annotation belongs to another snapshot or occurrence",
            ));
        }
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.annotation_owners",
                "complete metadata, definitions and annotations are required",
            ));
        }
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.annotation_owners",
                "annotation owner view budget exceeded",
            )
        };
        let broken = || {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.annotation_owners",
                "validated annotation owner facts are inconsistent",
            )
        };
        let mut visits = 0u64;
        let mut tick = || -> MddResult<()> {
            visits = visits.checked_add(1).ok_or_else(quota)?;
            if visits > limits.max_scanned_entries {
                return Err(quota());
            }
            Ok(())
        };
        let mut item = None;
        for candidate in &self.data.annotation_items {
            tick()?;
            if candidate.byte_offset == annotation.annotation_byte_offset
                && item.replace(candidate).is_some()
            {
                return Err(broken());
            }
        }
        let item = item.ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.annotation_owners",
                "annotation offset is not a physical item start",
            )
        })?;
        if item.encoded_range.byte_offset.0 != u64::from(item.byte_offset) {
            return Err(broken());
        }
        let mut matches = Vec::new();
        for owner in &self.data.owner_bindings {
            tick()?;
            let Some(offset) = owner.annotation_set_offset else {
                continue;
            };
            let mut selected = None;
            for set in &self.data.sets {
                tick()?;
                if set.byte_offset == offset && selected.replace(set).is_some() {
                    return Err(broken());
                }
            }
            let set = selected.ok_or_else(broken)?;
            if set.encoded_range.byte_offset.0 != u64::from(set.byte_offset) {
                return Err(broken());
            }
            for (ordinal, entry) in set.annotation_offsets.iter().enumerate() {
                tick()?;
                if *entry == item.byte_offset {
                    if u64::try_from(matches.len()).map_err(|_| quota())? >= limits.max_matches {
                        return Err(quota());
                    }
                    let set_ordinal = u32::try_from(ordinal).map_err(|_| quota())?;
                    matches.try_reserve(1).map_err(|_| quota())?;
                    matches.push(AnnotationOwnerFact {
                        source,
                        owner,
                        set,
                        annotation: item,
                        set_ordinal,
                    });
                }
            }
        }
        Ok(matches)
    }
    /// Iterate physical value nodes for one exact annotation item in parser order.
    /// The caller must consume the iterator and handle each error before calling
    /// the result complete. This does not infer an annotation owner or profile.
    pub fn annotation_value_facts(
        &self,
        annotation: &AnnotationRef,
        limits: AnnotationValueViewLimits,
    ) -> MddResult<impl Iterator<Item = MddResult<AnnotationValueFact<'_>>> + '_> {
        let source = self.source();
        if annotation.snapshot_id != source.snapshot_id
            || annotation.dex_occurrence_id != source.dex_occurrence_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.annotation_values",
                "annotation belongs to another snapshot or occurrence",
            ));
        }
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.annotation_values",
                "complete metadata, definitions and annotations are required",
            ));
        }
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.annotation_values",
                "annotation value view entry budget exceeded",
            )
        };
        let items = u64::try_from(self.data.annotation_items.len()).map_err(|_| quota())?;
        if items > limits.max_scanned_entries {
            return Err(quota());
        }
        let mut found = self
            .data
            .annotation_items
            .iter()
            .filter(|item| item.byte_offset == annotation.annotation_byte_offset);
        let item = found.next().ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.annotation_values",
                "annotation offset is not a physical item start",
            )
        })?;
        let inconsistent = || {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.annotation_values",
                "validated annotation values are inconsistent",
            )
        };
        if found.next().is_some() || item.encoded_range.byte_offset.0 != u64::from(item.byte_offset)
        {
            return Err(inconsistent());
        }
        let visits = u64::try_from(self.data.values.len())
            .ok()
            .and_then(|count| count.checked_mul(2))
            .and_then(|count| count.checked_add(items))
            .and_then(|count| count.checked_add(item.elements.len() as u64))
            .ok_or_else(quota)?;
        if visits > limits.max_scanned_entries {
            return Err(quota());
        }
        for (ordinal, node_id) in item.elements.iter().enumerate() {
            let value = self
                .data
                .values
                .get(*node_id as usize)
                .ok_or_else(inconsistent)?;
            if value.node_id != *node_id
                || value.annotation_byte_offset != Some(item.byte_offset)
                || value.depth != 0
                || u32::try_from(ordinal).ok() != Some(value.ordinal)
            {
                return Err(inconsistent());
            }
        }
        let count = u64::try_from(
            self.data
                .values
                .iter()
                .filter(|value| value.annotation_byte_offset == Some(item.byte_offset))
                .count(),
        )
        .map_err(|_| quota())?;
        if count > limits.max_values {
            return Err(quota());
        }
        if count < item.elements.len() as u64 {
            return Err(inconsistent());
        }
        let item_start = item.encoded_range.byte_offset.0;
        let item_end = item_start
            .checked_add(item.encoded_range.byte_length.0)
            .ok_or_else(inconsistent)?;
        if item.encoded_range.byte_length.0 == 0
            || usize::try_from(item_end).map_or(true, |end| end > self.bytes().len())
        {
            return Err(inconsistent());
        }
        Ok(self
            .data
            .values
            .iter()
            .enumerate()
            .filter(move |(_, value)| value.annotation_byte_offset == Some(item.byte_offset))
            .map(move |(ordinal, value)| {
                let start = value.encoded_range.byte_offset.0;
                let end = start
                    .checked_add(value.encoded_range.byte_length.0)
                    .ok_or_else(inconsistent)?;
                if u32::try_from(ordinal).ok() != Some(value.node_id)
                    || value.encoded_range.byte_length.0 == 0
                    || start < item_start
                    || end > item_end
                {
                    return Err(inconsistent());
                }
                let start = usize::try_from(start).map_err(|_| inconsistent())?;
                let end = usize::try_from(end).map_err(|_| inconsistent())?;
                let raw_encoded = self.bytes().get(start..end).ok_or_else(inconsistent)?;
                Ok(AnnotationValueFact {
                    source,
                    annotation: item,
                    value,
                    raw_encoded,
                })
            }))
    }
    /// Resolve one encoded call_site_id without scanning all bindings. A
    /// missing index returns None only for complete facts in this occurrence.
    /// The limits count two logical lookups and one returned binding, not CPU,
    /// bytes, allocation, cancellation or RSS.
    pub fn encoded_call_site(
        &self,
        reference: &EncodedCallSiteRef,
        limits: AnnotationOwnerViewLimits,
    ) -> MddResult<Option<EncodedCallSiteView<'_>>> {
        let stage = "facts.encoded_call_site";
        let source = self.source();
        if reference.snapshot_id != source.snapshot_id
            || reference.dex_occurrence_id != source.dex_occurrence_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                stage,
                "call site belongs to another snapshot or occurrence",
            ));
        }
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                stage,
                "complete metadata, definitions and annotations are required",
            ));
        }
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                stage,
                "call-site view budget exceeded",
            )
        };
        let inconsistent = || {
            MddError::new(
                ErrorCode::InternalFault,
                stage,
                "validated call-site binding is inconsistent",
            )
        };
        if limits.max_scanned_entries < 1 {
            return Err(quota());
        }
        let Some(binding) = usize::try_from(reference.call_site_idx)
            .ok()
            .and_then(|index| self.data.call_site_arrays.get(index))
        else {
            return Ok(None);
        };
        if limits.max_scanned_entries < 2 || limits.max_matches < 1 {
            return Err(quota());
        }
        if binding.call_site_idx != reference.call_site_idx {
            return Err(inconsistent());
        }
        let array = usize::try_from(binding.encoded_array_index)
            .ok()
            .and_then(|index| self.data.encoded_arrays.get(index))
            .ok_or_else(inconsistent)?;
        if array.byte_offset != binding.encoded_array_byte_offset
            || array.encoded_range.byte_offset.0 != u64::from(array.byte_offset)
            || array.encoded_range.byte_length.0 == 0
        {
            return Err(inconsistent());
        }
        let start =
            usize::try_from(array.encoded_range.byte_offset.0).map_err(|_| inconsistent())?;
        let length =
            usize::try_from(array.encoded_range.byte_length.0).map_err(|_| inconsistent())?;
        let end = start.checked_add(length).ok_or_else(inconsistent)?;
        let raw_encoded = self.bytes().get(start..end).ok_or_else(inconsistent)?;
        Ok(Some(EncodedCallSiteView {
            source,
            binding,
            array,
            raw_encoded,
        }))
    }
    /// Return encoded references to one physical array without deduplicating
    /// classes or call sites. An empty result means this complete occurrence
    /// contains no such encoded bindings; it makes no runtime claim.
    /// Limits count scanned entries and returned bindings, not bytes or RSS.
    pub fn encoded_array_bindings(
        &self,
        reference: &EncodedArrayRef,
        limits: AnnotationOwnerViewLimits,
    ) -> MddResult<EncodedArrayBindings<'_>> {
        let stage = "facts.encoded_array_bindings";
        let source = self.source();
        if reference.snapshot_id != source.snapshot_id
            || reference.dex_occurrence_id != source.dex_occurrence_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                stage,
                "array belongs to another snapshot or occurrence",
            ));
        }
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                stage,
                "complete metadata, definitions and annotations are required",
            ));
        }
        let quota = || MddError::new(ErrorCode::QuotaExceeded, stage, "binding budget exceeded");
        let inconsistent = || {
            MddError::new(
                ErrorCode::InternalFault,
                stage,
                "validated array binding is inconsistent",
            )
        };
        let classes = &self.definitions.definitions.classes;
        let call_sites = &self.data.call_site_arrays;
        let arrays = &self.data.encoded_arrays;
        let visits = u64::try_from(arrays.len())
            .ok()
            .and_then(|n| n.checked_add(u64::try_from(classes.len()).ok()?))
            .and_then(|n| n.checked_add(u64::try_from(call_sites.len()).ok()?))
            .ok_or_else(quota)?;
        if visits > limits.max_scanned_entries {
            return Err(quota());
        }
        let mut matching = arrays
            .iter()
            .enumerate()
            .filter(|(_, array)| array.byte_offset == reference.byte_offset);
        let (array_index, array) = matching.next().ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                stage,
                "array offset is not a physical item start",
            )
        })?;
        if matching.next().is_some()
            || array.encoded_range.byte_offset.0 != u64::from(array.byte_offset)
        {
            return Err(inconsistent());
        }
        let mut bindings = Vec::new();
        for (index, class) in classes.iter().enumerate() {
            if class
                .static_values_byte_offset
                .is_some_and(|offset| offset.0 == u64::from(array.byte_offset))
            {
                if u32::try_from(index).ok() != Some(class.class_def_idx) {
                    return Err(inconsistent());
                }
                if u64::try_from(bindings.len()).map_err(|_| quota())? >= limits.max_matches {
                    return Err(quota());
                }
                bindings.try_reserve(1).map_err(|_| quota())?;
                bindings.push(EncodedArrayBinding::StaticValues(class));
            }
        }
        for (index, binding) in call_sites.iter().enumerate() {
            if binding.encoded_array_byte_offset == array.byte_offset {
                if u32::try_from(index).ok() != Some(binding.call_site_idx)
                    || usize::try_from(binding.encoded_array_index).ok() != Some(array_index)
                {
                    return Err(inconsistent());
                }
                if u64::try_from(bindings.len()).map_err(|_| quota())? >= limits.max_matches {
                    return Err(quota());
                }
                bindings.try_reserve(1).map_err(|_| quota())?;
                bindings.push(EncodedArrayBinding::CallSite(binding));
            }
        }
        Ok(EncodedArrayBindings {
            source,
            array,
            bindings,
        })
    }
    /// Resolve one node without materializing the complete array value view.
    /// `None` means the node is not present in this physical array, including
    /// when the same node ID refers to a value in another array. Limits count
    /// scanned physical arrays and a node lookup, not CPU, bytes or RSS.
    pub fn encoded_array_value(
        &self,
        reference: &EncodedArrayValueRef,
        limits: AnnotationValueViewLimits,
    ) -> MddResult<Option<EncodedArrayValueView<'_>>> {
        let stage = "facts.encoded_array_value";
        let source = self.source();
        if reference.array.snapshot_id != source.snapshot_id
            || reference.array.dex_occurrence_id != source.dex_occurrence_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                stage,
                "array belongs to another snapshot or occurrence",
            ));
        }
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                stage,
                "complete metadata, definitions and annotations are required",
            ));
        }
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                stage,
                "array value budget exceeded",
            )
        };
        let inconsistent = || {
            MddError::new(
                ErrorCode::InternalFault,
                stage,
                "validated encoded array value is inconsistent",
            )
        };
        let visits = u64::try_from(self.data.encoded_arrays.len())
            .ok()
            .and_then(|n| n.checked_add(1))
            .ok_or_else(quota)?;
        if visits > limits.max_scanned_entries {
            return Err(quota());
        }
        let mut matches = self
            .data
            .encoded_arrays
            .iter()
            .filter(|array| array.byte_offset == reference.array.byte_offset);
        let array = matches.next().ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                stage,
                "array offset is not a physical item start",
            )
        })?;
        if matches.next().is_some()
            || array.encoded_range.byte_offset.0 != u64::from(array.byte_offset)
        {
            return Err(inconsistent());
        }
        let start = array.encoded_range.byte_offset.0;
        let end = start
            .checked_add(array.encoded_range.byte_length.0)
            .ok_or_else(inconsistent)?;
        if start == end
            || usize::try_from(end)
                .ok()
                .is_none_or(|end| end > self.bytes().len())
        {
            return Err(inconsistent());
        }
        let Some(value) = usize::try_from(reference.node_id)
            .ok()
            .and_then(|id| self.data.values.get(id))
        else {
            return Ok(None);
        };
        if value.node_id != reference.node_id {
            return Err(inconsistent());
        }
        let value_start = value.encoded_range.byte_offset.0;
        if value_start <= start || value_start >= end {
            return Ok(None);
        }
        let value_end = value_start
            .checked_add(value.encoded_range.byte_length.0)
            .ok_or_else(inconsistent)?;
        if value.annotation_byte_offset.is_some() || value_start == value_end || value_end > end {
            return Err(inconsistent());
        }
        if limits.max_values == 0 {
            return Err(quota());
        }
        let raw_encoded = self
            .bytes()
            .get(
                usize::try_from(value_start).map_err(|_| inconsistent())?
                    ..usize::try_from(value_end).map_err(|_| inconsistent())?,
            )
            .ok_or_else(inconsistent)?;
        Ok(Some(EncodedArrayValueView {
            source,
            array,
            value,
            raw_encoded,
        }))
    }

    /// Resolve a physically walked encoded-array item and its value nodes.
    /// Limits bound logical visits and returned nodes, not memory or CPU time.
    /// Shared references do not duplicate the physical item in this view.
    pub fn encoded_array_view(
        &self,
        reference: &EncodedArrayRef,
        limits: AnnotationValueViewLimits,
    ) -> MddResult<EncodedArrayView<'_>> {
        let stage = "facts.encoded_array";
        let source = self.source();
        if reference.snapshot_id != source.snapshot_id
            || reference.dex_occurrence_id != source.dex_occurrence_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                stage,
                "array belongs to another snapshot or occurrence",
            ));
        }
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                stage,
                "complete metadata, definitions and annotations are required",
            ));
        }
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                stage,
                "encoded array view entry budget exceeded",
            )
        };
        let inconsistent = || {
            MddError::new(
                ErrorCode::InternalFault,
                stage,
                "validated encoded array is inconsistent",
            )
        };
        let arrays = u64::try_from(self.data.encoded_arrays.len()).map_err(|_| quota())?;
        if arrays > limits.max_scanned_entries {
            return Err(quota());
        }
        let mut matches = self
            .data
            .encoded_arrays
            .iter()
            .filter(|array| array.byte_offset == reference.byte_offset);
        let array = matches.next().ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                stage,
                "array offset is not a physical item start",
            )
        })?;
        if matches.next().is_some()
            || array.encoded_range.byte_offset.0 != u64::from(array.byte_offset)
        {
            return Err(inconsistent());
        }
        let visits = u64::try_from(self.data.values.len())
            .ok()
            .and_then(|v| v.checked_mul(2))
            .and_then(|v| v.checked_add(arrays))
            .and_then(|v| v.checked_add(u64::try_from(array.elements.len()).ok()?))
            .ok_or_else(quota)?;
        if visits > limits.max_scanned_entries {
            return Err(quota());
        }
        let start = array.encoded_range.byte_offset.0;
        let end = start
            .checked_add(array.encoded_range.byte_length.0)
            .ok_or_else(inconsistent)?;
        if start == end {
            return Err(inconsistent());
        }
        let start_usize = usize::try_from(start).map_err(|_| inconsistent())?;
        let end_usize = usize::try_from(end).map_err(|_| inconsistent())?;
        let raw_encoded = self
            .bytes()
            .get(start_usize..end_usize)
            .ok_or_else(inconsistent)?;
        for (ordinal, id) in array.elements.iter().enumerate() {
            let node = self
                .data
                .values
                .get(*id as usize)
                .ok_or_else(inconsistent)?;
            if node.node_id != *id
                || node.annotation_byte_offset.is_some()
                || node.depth != 0
                || node.name_idx.is_some()
                || u32::try_from(ordinal).ok() != Some(node.ordinal)
                || node.encoded_range.byte_offset.0 <= start
                || node.encoded_range.byte_offset.0 >= end
            {
                return Err(inconsistent());
            }
        }
        let in_array = |node: &&EncodedValue| {
            node.annotation_byte_offset.is_none()
                && node.encoded_range.byte_offset.0 > start
                && node.encoded_range.byte_offset.0 < end
        };
        let count = self.data.values.iter().filter(in_array).count();
        if u64::try_from(count).map_err(|_| quota())? > limits.max_values {
            return Err(quota());
        }
        if count < array.elements.len() {
            return Err(inconsistent());
        }
        let mut values = Vec::new();
        values.try_reserve_exact(count).map_err(|_| quota())?;
        for (ordinal, value) in self
            .data
            .values
            .iter()
            .enumerate()
            .filter(|(_, value)| in_array(value))
        {
            let value_start = value.encoded_range.byte_offset.0;
            let value_end = value_start
                .checked_add(value.encoded_range.byte_length.0)
                .ok_or_else(inconsistent)?;
            if u32::try_from(ordinal).ok() != Some(value.node_id)
                || value_start == value_end
                || value_end > end
            {
                return Err(inconsistent());
            }
            let raw = self
                .bytes()
                .get(
                    usize::try_from(value_start).map_err(|_| inconsistent())?
                        ..usize::try_from(value_end).map_err(|_| inconsistent())?,
                )
                .ok_or_else(inconsistent)?;
            values.push(EncodedArrayValueFact {
                value,
                raw_encoded: raw,
            });
        }
        Ok(EncodedArrayView {
            source,
            array,
            raw_encoded,
            values,
        })
    }
}
