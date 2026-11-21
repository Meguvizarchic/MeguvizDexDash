use super::*;

impl AnnotationFacts {
    /// Resolve the physical encoded parameter-annotation list for one method.
    /// `None` means no such binding was encoded in this complete DEX occurrence;
    /// it does not prove absence from another source or at runtime. A present list
    /// can have unknown prototype-position coverage and is never padded.
    /// Limits bound logical scan entries and encoded slots, not CPU or RSS.
    pub fn method_encoded_parameter_list(
        &self,
        method: &EntityRef,
        limits: ParameterViewLimits,
    ) -> MddResult<Option<EncodedParameterListFact<'_>>> {
        let source = self.source();
        if method.snapshot_id != source.snapshot_id
            || method.dex_occurrence_id != source.dex_occurrence_id
            || !matches!(
                method.kind,
                EntityKind::MethodReference | EntityKind::MethodDefinition
            )
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.parameters",
                "method is foreign or has the wrong identity kind",
            ));
        }
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.parameters",
                "complete metadata, definitions and annotations are required",
            ));
        }
        let defs = self.definitions.definitions();
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.parameters",
                "encoded parameter list budget exceeded",
            )
        };
        let broken = || {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.parameters",
                "validated parameter list is inconsistent",
            )
        };
        let scans = [
            defs.method_definitions.len(),
            self.data.parameter_lists.len(),
            self.data.ref_lists.len(),
        ]
        .into_iter()
        .try_fold(0u64, |total, len| {
            u64::try_from(len).ok().and_then(|n| total.checked_add(n))
        })
        .ok_or_else(quota)?;
        if scans > limits.max_scan_entries {
            return Err(quota());
        }
        let reference = defs
            .method_references
            .get(method.local_index as usize)
            .filter(|r| r.method_idx == method.local_index)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.parameters",
                    "method reference does not exist in this occurrence",
                )
            })?;
        let mut definitions = defs
            .method_definitions
            .iter()
            .filter(|d| d.method_idx == method.local_index);
        let definition = definitions.next();
        if definitions.next().is_some() {
            return Err(broken());
        }
        if method.kind == EntityKind::MethodDefinition && definition.is_none() {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.parameters",
                "method definition does not exist in this occurrence",
            ));
        }
        let mut bindings = self
            .data
            .parameter_lists
            .iter()
            .filter(|b| b.method_idx == method.local_index);
        let Some(binding) = bindings.next() else {
            return Ok(None);
        };
        if bindings.next().is_some() {
            return Err(broken());
        }
        if !binding.encoded_slots_complete {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.parameters",
                "encoded parameter slots are incomplete",
            ));
        }
        let mut lists = self
            .data
            .ref_lists
            .iter()
            .filter(|list| list.byte_offset == binding.ref_list_byte_offset);
        let list = lists.next().ok_or_else(broken)?;
        if lists.next().is_some()
            || u64::try_from(list.annotation_set_offsets.len()).map_err(|_| quota())?
                != u64::from(binding.encoded_slot_count)
            || list.encoded_range.byte_offset.0 != u64::from(list.byte_offset)
        {
            return Err(broken());
        }
        if u64::from(binding.encoded_slot_count) > limits.max_parameters {
            return Err(quota());
        }
        let start = usize::try_from(list.encoded_range.byte_offset.0).map_err(|_| broken())?;
        let end = list
            .encoded_range
            .byte_offset
            .0
            .checked_add(list.encoded_range.byte_length.0)
            .and_then(|v| usize::try_from(v).ok())
            .ok_or_else(broken)?;
        let raw_encoded = self.bytes().get(start..end).ok_or_else(broken)?;
        Ok(Some(EncodedParameterListFact {
            source,
            method_reference: reference,
            definition,
            binding,
            list,
            raw_encoded,
        }))
    }

    /// Resolve the encoded slots for a method without inventing prototype
    /// positions. `None` means no encoded binding; `Some` may contain zero
    /// slots. `max_set_visits` bounds physical set entries scanned per complete
    /// iterator pass, separately from the method/list and slot limits. These
    /// are logical bounds and do not bound CPU, allocator overhead, or RSS.
    pub fn method_encoded_parameter_slots(
        &self,
        method: &EntityRef,
        limits: ParameterViewLimits,
        max_set_visits: u64,
    ) -> MddResult<Option<EncodedParameterSlots<'_>>> {
        let Some(encoded) = self.method_encoded_parameter_list(method, limits)? else {
            return Ok(None);
        };
        let nonzero = u64::try_from(
            encoded
                .list
                .annotation_set_offsets
                .iter()
                .filter(|offset| offset.is_some())
                .count(),
        )
        .map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.parameters",
                "set scan overflow",
            )
        })?;
        let visits = nonzero
            .checked_mul(u64::try_from(self.data.sets.len()).map_err(|_| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "facts.parameters",
                    "set scan overflow",
                )
            })?)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "facts.parameters",
                    "set scan overflow",
                )
            })?;
        if visits > max_set_visits {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.parameters",
                "parameter set scan budget exceeded",
            ));
        }
        Ok(Some(EncodedParameterSlots {
            source: encoded.source,
            binding: encoded.binding,
            list: encoded.list,
            sets: &self.data.sets,
            bytes: self.bytes(),
        }))
    }

    /// Bind one method to proven prototype positions and physical annotation slots.
    /// A short or otherwise unmapped list is not padded and is reported incomplete.
    pub fn method_parameter_facts(
        &self,
        method: &EntityRef,
        limits: ParameterViewLimits,
    ) -> MddResult<MethodParameterFacts<'_>> {
        let source = self.source();
        if method.snapshot_id != source.snapshot_id
            || method.dex_occurrence_id != source.dex_occurrence_id
            || !matches!(
                method.kind,
                EntityKind::MethodReference | EntityKind::MethodDefinition
            )
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.parameters",
                "method is foreign or has the wrong identity kind",
            ));
        }
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.parameters",
                "complete metadata, definitions and annotations are required",
            ));
        }
        let definitions = self.definitions.definitions();
        let scan_count = [
            definitions.method_definitions.len(),
            self.data.parameter_lists.len(),
            self.data.ref_lists.len(),
        ]
        .into_iter()
        .try_fold(0u64, |total, len| {
            u64::try_from(len)
                .ok()
                .and_then(|len| total.checked_add(len))
        })
        .ok_or_else(|| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.parameters",
                "parameter view scan budget overflow",
            )
        })?;
        if scan_count > limits.max_scan_entries {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.parameters",
                "parameter view scan budget exceeded",
            ));
        }
        let broken = || {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.parameters",
                "validated parameter facts are inconsistent",
            )
        };
        let reference = definitions
            .method_references
            .get(method.local_index as usize)
            .filter(|reference| reference.method_idx == method.local_index)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.parameters",
                    "method reference does not exist in this occurrence",
                )
            })?;
        let mut matches = definitions
            .method_definitions
            .iter()
            .filter(|entry| entry.method_idx == method.local_index);
        let definition = matches.next();
        if matches.next().is_some() {
            return Err(broken());
        }
        if method.kind == EntityKind::MethodDefinition && definition.is_none() {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.parameters",
                "method definition does not exist in this occurrence",
            ));
        }
        let prototype = self
            .definitions
            .metadata()
            .prototypes()
            .get(reference.proto_idx as usize)
            .map(|fact| &fact.data)
            .filter(|prototype| prototype.proto_idx == reference.proto_idx)
            .ok_or_else(broken)?;
        let count = u64::try_from(prototype.parameter_type_indices.len()).map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.parameters",
                "parameter count overflow",
            )
        })?;
        if count > limits.max_parameters || count > u64::from(u32::MAX) {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.parameters",
                "parameter count budget exceeded",
            ));
        }
        for index in &prototype.parameter_type_indices {
            if !self
                .definitions
                .metadata()
                .types()
                .get(*index as usize)
                .is_some_and(|fact| fact.data.type_idx == *index)
            {
                return Err(broken());
            }
        }
        let mut bindings = self
            .data
            .parameter_lists
            .iter()
            .filter(|binding| binding.method_idx == method.local_index);
        let binding = bindings.next();
        if bindings.next().is_some() {
            return Err(broken());
        }
        let encoded_list = if let Some(binding) = binding {
            if !binding.encoded_slots_complete
                || binding.prototype_position_coverage != Completeness::Complete
            {
                return Err(MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.parameters",
                    "prototype positions for encoded annotation slots are not complete",
                )
                .detail("required_layer", "prototype_parameter_annotation_positions"));
            }
            if u64::from(binding.prototype_parameter_count) != count
                || u64::from(binding.encoded_slot_count) != count
            {
                return Err(broken());
            }
            let mut lists = self
                .data
                .ref_lists
                .iter()
                .filter(|list| list.byte_offset == binding.ref_list_byte_offset);
            let list = lists.next().ok_or_else(broken)?;
            if lists.next().is_some()
                || list.annotation_set_offsets.len() != prototype.parameter_type_indices.len()
            {
                return Err(broken());
            }
            Some(list)
        } else {
            None
        };
        Ok(MethodParameterFacts {
            facts: self,
            method_reference: reference,
            definition,
            prototype,
            encoded_list,
        })
    }
    pub fn data(&self) -> &DexAnnotations {
        &self.data
    }
    pub fn signatures(&self) -> &[SignatureFact] {
        &self.signatures
    }

    /// Resolve one borrowed Signature owner's parameter-position status without
    /// treating an encoded slot as a proven prototype position. The Signature
    /// must match a stored Signature's stable source identity and full content;
    /// an equivalent clone is accepted, while a foreign or changed value is
    /// rejected. Repeated Signature occurrences remain separate.
    pub fn signature_parameter_position(
        &self,
        signature: &SignatureFact,
        limits: SignaturePositionLimits,
    ) -> MddResult<SignatureParameterPosition> {
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.signatures",
                "signature identity scan budget exceeded",
            )
        };
        let broken = || {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.signatures",
                "signature owner and parameter list are inconsistent",
            )
        };
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.signatures",
                "complete metadata, definitions and annotations are required",
            ));
        }
        if u64::try_from(self.signatures.len()).map_err(|_| quota())? > limits.max_signatures {
            return Err(quota());
        }
        // Compare against the immutable stored facts rather than accepting the
        // caller's fields as evidence. Bound variable-width comparisons before
        // touching the corresponding contents, including every part identity.
        let mut examined = 0u64;
        let mut account = |amount: u64| -> MddResult<()> {
            examined = examined.checked_add(amount).ok_or_else(quota)?;
            if examined > limits.max_identity_bytes {
                return Err(quota());
            }
            Ok(())
        };
        let mut account_signature = |item: &SignatureFact| -> MddResult<()> {
            account(128)?;
            account(
                u64::try_from(item.utf16_units.len())
                    .map_err(|_| quota())?
                    .checked_mul(2)
                    .ok_or_else(quota)?,
            )?;
            account(
                u64::try_from(item.parts.len())
                    .map_err(|_| quota())?
                    .checked_mul(32)
                    .ok_or_else(quota)?,
            )?;
            for length in [
                item.annotation.snapshot_id.len(),
                item.annotation.dex_occurrence_id.len(),
                item.owner.reference.snapshot_id.len(),
                item.owner.reference.dex_occurrence_id.len(),
                item.string_pool_id.len(),
            ] {
                account(u64::try_from(length).map_err(|_| quota())?)?;
            }
            if let Some(definition) = &item.owner.definition {
                account(u64::try_from(definition.snapshot_id.len()).map_err(|_| quota())?)?;
                account(u64::try_from(definition.dex_occurrence_id.len()).map_err(|_| quota())?)?;
            }
            for part in &item.parts {
                account(u64::try_from(part.snapshot_id.len()).map_err(|_| quota())?)?;
                account(u64::try_from(part.dex_occurrence_id.len()).map_err(|_| quota())?)?;
            }
            Ok(())
        };
        account_signature(signature)?;
        let mut found = false;
        for item in &self.signatures {
            account_signature(item)?;
            if item.annotation == signature.annotation
                && item.owner.kind == signature.owner.kind
                && item.owner.reference == signature.owner.reference
                && item.owner.definition == signature.owner.definition
                && item.owner.parameter_ordinal == signature.owner.parameter_ordinal
                && item.string_pool_id == signature.string_pool_id
                && item.parts == signature.parts
                && item.utf16_units == signature.utf16_units
            {
                found = true;
                break;
            }
        }
        if !found {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.signatures",
                "signature does not match this occurrence",
            ));
        }
        if signature.owner.kind != AnnotationOwnerKind::Parameter {
            if signature.owner.parameter_ordinal.is_some() {
                return Err(broken());
            }
            return Ok(SignatureParameterPosition::NotParameter);
        }
        if signature.owner.reference.kind != EntityKind::MethodReference {
            return Err(broken());
        }
        let slot = signature.owner.parameter_ordinal.ok_or_else(broken)?;
        let owners = self.annotation_owner_facts(&signature.annotation, limits.owners)?;
        let mut matches = owners.iter().filter(|item| {
            item.owner.kind == AnnotationOwnerKind::Parameter
                && item.owner.local_index == signature.owner.reference.local_index
                && item.owner.parameter_ordinal == Some(slot)
        });
        let owner = matches.next().ok_or_else(broken)?;
        if matches.next().is_some() {
            return Err(broken());
        }
        let encoded = self
            .method_encoded_parameter_list(&signature.owner.reference, limits.parameters)?
            .ok_or_else(broken)?;
        if encoded.binding.class_def_idx != owner.owner.class_def_idx
            || encoded.list.annotation_set_offsets.get(slot as usize)
                != Some(&owner.owner.annotation_set_offset)
            || owner.owner.prototype_parameter_count
                != Some(encoded.binding.prototype_parameter_count)
        {
            return Err(broken());
        }
        match encoded.binding.prototype_position_coverage {
            Completeness::Complete
                if slot < encoded.binding.prototype_parameter_count
                    && owner.owner.parameter_position_in_prototype == Some(true) =>
            {
                Ok(SignatureParameterPosition::Known { ordinal: slot })
            }
            Completeness::Unknown if owner.owner.parameter_position_in_prototype.is_none() => {
                Ok(SignatureParameterPosition::Unknown { encoded_slot: slot })
            }
            Completeness::Partial => Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.signatures",
                "prototype parameter-position coverage is incomplete",
            )),
            _ => Err(broken()),
        }
    }

    /// Borrow every encoded class, field, or method Signature for an exact
    /// owner in this DEX occurrence. Method and parameter annotations remain
    /// separate: parameter slots are intentionally not selected here. Repeated
    /// signatures retain their encoded order and are not collapsed to one value.
    ///
    /// An empty iterator means no matching Signature in the complete annotation
    /// facts for this occurrence only; it does not assert runtime absence,
    /// inheritance, or the absence of annotations in another source.
    /// `max_scanned_entries` bounds logical visits, including both passes and
    /// definition identity validation, not allocation, CPU time, or RSS.
    pub fn owner_signatures(
        &self,
        owner: &EntityRef,
        limits: SignatureViewLimits,
    ) -> MddResult<impl Iterator<Item = &SignatureFact> + '_> {
        let source = self.source();
        if owner.snapshot_id != source.snapshot_id
            || owner.dex_occurrence_id != source.dex_occurrence_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.signatures",
                "owner belongs to another snapshot or DEX occurrence",
            ));
        }
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.signatures",
                "complete metadata, definitions and annotations are required",
            ));
        }
        let (kind, definition_scan) = match owner.kind {
            EntityKind::ClassDefinition => (AnnotationOwnerKind::Class, 0usize),
            EntityKind::FieldReference => (AnnotationOwnerKind::Field, 0),
            EntityKind::FieldDefinition => (
                AnnotationOwnerKind::Field,
                self.definitions.definitions().field_definitions.len(),
            ),
            EntityKind::MethodReference => (AnnotationOwnerKind::Method, 0),
            EntityKind::MethodDefinition => (
                AnnotationOwnerKind::Method,
                self.definitions.definitions().method_definitions.len(),
            ),
            _ => {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.signatures",
                    "owner must be a class, field, or method entity",
                ));
            }
        };
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.signatures",
                "signature owner view budget exceeded",
            )
        };
        let visits = u64::try_from(self.signatures.len())
            .ok()
            .and_then(|count| count.checked_mul(2))
            .and_then(|count| u64::try_from(definition_scan).ok()?.checked_add(count))
            .ok_or_else(quota)?;
        if visits > limits.max_scanned_entries {
            return Err(quota());
        }
        // Validate the exact requested identity, including definition/reference
        // distinction, before returning an empty result.
        self.definitions.entity(owner.kind, owner.local_index)?;
        let local_index = owner.local_index;
        let matches = move |fact: &&SignatureFact| {
            fact.owner.kind == kind
                && fact.owner.reference.local_index == local_index
                && fact.owner.parameter_ordinal.is_none()
        };
        let count =
            u64::try_from(self.signatures.iter().filter(matches).count()).map_err(|_| quota())?;
        if count > limits.max_matches {
            return Err(quota());
        }
        Ok(self.signatures.iter().filter(matches))
    }
    pub fn completed_layers(&self) -> &[String] {
        &self.completed_layers
    }
    pub fn unbuilt_layers(&self) -> &[String] {
        &self.unbuilt_layers
    }
    pub fn annotation_coverage(&self) -> Completeness {
        self.annotation_coverage
    }
    pub fn require_complete_parameter_positions(&self) -> MddResult<()> {
        if self
            .data
            .parameter_lists
            .iter()
            .any(|binding| binding.prototype_position_coverage != Completeness::Complete)
        {
            return Err(MddError::new(ErrorCode::IncompleteFacts,"facts.annotations","encoded parameter slots are complete, but complete prototype-position coverage is not established")
                .detail("required_layer","prototype_parameter_annotation_positions").detail("snapshot_id",self.source().snapshot_id.clone()).detail("dex_occurrence_id",self.source().dex_occurrence_id.clone()));
        }
        Ok(())
    }
}
