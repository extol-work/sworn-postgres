-- Preload a lookup table of activity type URIs this reference implementation
-- recognizes. The table is not required for correctness: any well-formed URI
-- remains a valid activity type per SWORN spec §2.2. The table exists so that
-- clients can enumerate "which vocabularies does this instance speak?" without
-- inventing a discovery mechanism.
--
-- Populated at migration time with the CRediT taxonomy (spec §9.1.1). Other
-- vocabularies (Extol app vocab, sworn.dev/v1/ well-known types) are
-- documented in the spec but not preloaded here; they are use-case-specific.

CREATE TABLE known_activity_types (
    uri         TEXT PRIMARY KEY,
    label       TEXT NOT NULL,
    description TEXT NOT NULL,
    source      TEXT NOT NULL,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- CRediT — ANSI/NISO Z39.104-2022. Fourteen contributor roles for research
-- output attribution. Slug pattern follows JATS4R's encoding.
INSERT INTO known_activity_types (uri, label, description, source) VALUES
    ('credit.niso.org/contributor-roles/conceptualization/',
     'Conceptualization',
     'Ideas; formulation of overarching research goals and aims.',
     'CRediT'),
    ('credit.niso.org/contributor-roles/data-curation/',
     'Data curation',
     'Management activities to annotate, scrub, and maintain research data.',
     'CRediT'),
    ('credit.niso.org/contributor-roles/formal-analysis/',
     'Formal analysis',
     'Statistical, mathematical, or computational analysis of study data.',
     'CRediT'),
    ('credit.niso.org/contributor-roles/funding-acquisition/',
     'Funding acquisition',
     'Acquisition of financial support for the project.',
     'CRediT'),
    ('credit.niso.org/contributor-roles/investigation/',
     'Investigation',
     'Conducting the research process; performing experiments or evidence collection.',
     'CRediT'),
    ('credit.niso.org/contributor-roles/methodology/',
     'Methodology',
     'Development or design of methodology; creation of models.',
     'CRediT'),
    ('credit.niso.org/contributor-roles/project-administration/',
     'Project administration',
     'Management and coordination of the research activity.',
     'CRediT'),
    ('credit.niso.org/contributor-roles/resources/',
     'Resources',
     'Provision of study materials, reagents, patients, samples, compute resources, etc.',
     'CRediT'),
    ('credit.niso.org/contributor-roles/software/',
     'Software',
     'Programming, software development, algorithm design, implementation, testing.',
     'CRediT'),
    ('credit.niso.org/contributor-roles/supervision/',
     'Supervision',
     'Oversight and leadership responsibility for the research activity.',
     'CRediT'),
    ('credit.niso.org/contributor-roles/validation/',
     'Validation',
     'Verification of the overall reproducibility of results and other experimental outputs.',
     'CRediT'),
    ('credit.niso.org/contributor-roles/visualization/',
     'Visualization',
     'Preparation, creation, and presentation of published work, specifically visualization.',
     'CRediT'),
    ('credit.niso.org/contributor-roles/writing-original-draft/',
     'Writing – original draft',
     'Preparation, creation, and presentation of published work, specifically writing the initial draft.',
     'CRediT'),
    ('credit.niso.org/contributor-roles/writing-review-editing/',
     'Writing – review & editing',
     'Critical review, commentary, or revision of published work.',
     'CRediT'),
    -- The reference example vocabulary shipped since CP2, kept here so
    -- callers can enumerate it alongside CRediT.
    ('sworn.dev/v1/endorsement',
     'Endorsement',
     'A general-purpose endorsement of the subject by the signer.',
     'sworn.dev');
