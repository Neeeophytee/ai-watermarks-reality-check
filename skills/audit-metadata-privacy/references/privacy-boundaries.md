# Privacy and provenance boundaries

## Review categories

- `location`: GPS coordinates or location names — high priority.
- `identity`: author, creator, owner, email, or username — medium/high depending on context.
- `device`: camera make/model or serial identifiers — medium.
- `software`: application and version — low/medium.
- `timeline`: creation and modification dates — low/medium.
- `comment`: free-form comments, descriptions, and labels — medium because contents are unpredictable.

## Safe release pattern

1. Preserve and hash the original.
2. Audit provenance and privacy separately.
3. Decide which disclosures are intentional.
4. Create a derivative with a format-aware tool if removal is authorized.
5. Re-sign or update provenance where appropriate.
6. Verify the released derivative and document the transformation.

Never delete an entire metadata block merely because one field is sensitive; it may contain provenance assertions or accessibility information.
