"""
Ghana / West Africa–specific phishing detection rules.

Categories:
  - MoMo fraud          : Mobile Money scams (PIN theft, fake credits, etc.)
  - Carrier impersonation: MTN, Telecel/Vodafone, AirtelTigo
  - Govt impersonation  : GRA, Electoral Commission, NIA, MASLOC
  - Financial fraud     : Ghanaian banks, investment scams, SSNIT
  - Delivery fraud      : GhanaPost, Kotoka customs
  - SIM / KYC fraud     : SIM swap, fake re-registration
  - Job fraud           : Fake GNPC, Cocobod, GES recruitments
  - Slang patterns      : Twi-influenced phishing language
"""

GH_RULES = [

    # ── Mobile Money (MoMo) ────────────────────────────────────────
    {
        "id": "momo_pin_request",
        "name": "MoMo PIN / wallet credential request",
        "weight": 35,
        "severity": "high",
        "region": "gh",
        "category": "MoMo fraud",
        "desc": "Requests MoMo PIN, wallet credentials, or account reset code",
        "pattern": (
            r"(?:momo (?:pin|password|wallet|account)"
            r"|mobile money (?:pin|password|account)"
            r"|send (?:your |the )?pin"
            r"|your (?:mtn |vodafone |airtel |telecel )?momo (?:pin|code|password)"
            r"|confirm (?:your )?momo"
            r"|reset (?:your )?momo"
            r"|momo (?:verification|security) code)"
        ),
    },
    {
        "id": "momo_accidental_transfer",
        "name": "MoMo accidental transfer lure",
        "weight": 32,
        "severity": "high",
        "region": "gh",
        "category": "MoMo fraud",
        "desc": '"I sent money to you by mistake, please return it"',
        "pattern": (
            r"(?:sent (?:you |to you )?(?:money|ghs|cedis|cash) (?:by )?mistake"
            r"|wrong (?:number|account|name).*send (?:back|it)"
            r"|please (?:return|send back|refund) (?:the |my )?(?:money|ghs|amount|cash)"
            r"|accidentally (?:transferred|sent)"
            r"|mistakenly (?:sent|transferred))"
        ),
    },
    {
        "id": "momo_agent_impersonation",
        "name": "Fake MoMo agent / merchant",
        "weight": 30,
        "severity": "high",
        "region": "gh",
        "category": "MoMo fraud",
        "desc": "Impersonates MoMo agent, requests deposit or reversal code",
        "pattern": (
            r"(?:momo agent|mobile money agent|momo merchant"
            r"|send to (?:our |my )?agent"
            r"|agent (?:number|code|pin)"
            r"|float (?:top.?up|request)"
            r"|momo (?:reversal|refund) (?:code|pin)"
            r"|confirm (?:the )?transaction (?:code|id))"
        ),
    },
    {
        "id": "momo_fake_credit",
        "name": "Fake MoMo credit notification",
        "weight": 28,
        "severity": "high",
        "region": "gh",
        "category": "MoMo fraud",
        "desc": 'Spoofed "you have received GHS X" with callback demand',
        "pattern": (
            r"(?:you have received ghs"
            r"|ghs [\d,.]+\s*(?:has been |)credited (?:to your|your)"
            r"|your momo (?:balance|wallet|account) has been (?:credited|topped up)"
            r"|transaction id.*please (?:call|contact|send))"
        ),
    },

    # ── MTN Ghana ──────────────────────────────────────────────────
    {
        "id": "mtn_impersonation",
        "name": "MTN Ghana impersonation",
        "weight": 30,
        "severity": "high",
        "region": "gh",
        "category": "Carrier impersonation",
        "desc": "Fake MTN alerts, account warnings, KYC, SIM block",
        "pattern": (
            r"(?:mtn (?:ghana|momo|customer (?:care|service)|account|sim|data"
            r"|airtime|loyalty|reward|promo|offer|pulse|fasos|ahomka)"
            r"|your mtn (?:account|sim|number|momo)"
            r"|mtn.*ghs|mtn.*verify|mtn.*suspended|mtn.*upgrade|mtn.*kyc"
            r"|dear (?:valued )?mtn)"
        ),
    },
    {
        "id": "mtn_prize_scam",
        "name": "MTN prize / loyalty draw scam",
        "weight": 32,
        "severity": "high",
        "region": "gh",
        "category": "Carrier impersonation",
        "desc": "Fake MTN weekly draw, cash prize, loyalty reward lures",
        "pattern": (
            r"(?:mtn.*(?:won|winner|prize|reward|cash|ghs|lucky|draw|raffle|congratulat)"
            r"|won.*mtn"
            r"|mtn (?:weekly|monthly|annual) (?:draw|promo|prize)"
            r"|mtn.*free (?:airtime|data|cash|money|iphone|samsung))"
        ),
    },

    # ── Telecel / Vodafone Ghana ────────────────────────────────────
    {
        "id": "telecel_impersonation",
        "name": "Telecel / Vodafone Ghana impersonation",
        "weight": 30,
        "severity": "high",
        "region": "gh",
        "category": "Carrier impersonation",
        "desc": "Fake Telecel/Vodafone account warnings, cash offers, KYC",
        "pattern": (
            r"(?:telecel (?:ghana|cash|momo|account|customer|prize|reward|offer|promo|sim|kyc|upgrade)"
            r"|vodafone (?:ghana|cash|momo|account|customer|prize|reward|offer|promo|sim)"
            r"|your (?:telecel|vodafone) (?:account|sim|momo|number)"
            r"|dear (?:valued )?(?:telecel|vodafone))"
        ),
    },

    # ── AirtelTigo ─────────────────────────────────────────────────
    {
        "id": "airteltigo_impersonation",
        "name": "AirtelTigo impersonation",
        "weight": 30,
        "severity": "high",
        "region": "gh",
        "category": "Carrier impersonation",
        "desc": "Fake AirtelTigo / Tigo Cash alerts and promotions",
        "pattern": (
            r"(?:airteltigo|airtel tigo|tigo cash"
            r"|tigo (?:ghana|momo|account|sim|promo|prize|reward)"
            r"|airtel (?:ghana|money|momo)"
            r"|your (?:airteltigo|tigo) (?:account|sim|momo|number))"
        ),
    },

    # ── Government impersonation ────────────────────────────────────
    {
        "id": "gra_impersonation",
        "name": "Ghana Revenue Authority (GRA) lure",
        "weight": 32,
        "severity": "high",
        "region": "gh",
        "category": "Govt impersonation",
        "desc": "Fake GRA tax refund, penalty, TIN compliance notice",
        "pattern": (
            r"(?:ghana revenue authority"
            r"|gra (?:ghana|tax|refund|penalty|compliance|tin|levy)"
            r"|tax (?:refund|rebate|penalty) from (?:gra|government)"
            r"|gra.*verify|tin number.*gra|gra.*outstanding|gra.*arrest|gra.*court)"
        ),
    },
    {
        "id": "ec_impersonation",
        "name": "Electoral Commission (EC) lure",
        "weight": 28,
        "severity": "high",
        "region": "gh",
        "category": "Govt impersonation",
        "desc": "Fake EC voter card, biometric update, registration",
        "pattern": (
            r"(?:electoral commission|ec ghana|ghana electoral"
            r"|voter (?:id|card|registration|biometric|update)"
            r"|biometric (?:registration|verification|update).*ec"
            r"|new voter card|voter card.*collect|ghana card.*voter)"
        ),
    },
    {
        "id": "nia_impersonation",
        "name": "NIA / Ghana Card impersonation",
        "weight": 28,
        "severity": "high",
        "region": "gh",
        "category": "Govt impersonation",
        "desc": "Fake Ghana Card renewal, NIA verification, card suspension",
        "pattern": (
            r"(?:national identification authority|nia ghana"
            r"|ghana card (?:expired|renewal|update|verify|collection|blocked)"
            r"|your ghana card (?:has|is)"
            r"|update (?:your )?ghana card"
            r"|ghanacard.*(?:verify|suspended))"
        ),
    },
    {
        "id": "govt_loan_scam",
        "name": "Fake government loan / grant",
        "weight": 30,
        "severity": "high",
        "region": "gh",
        "category": "Govt impersonation",
        "desc": "Fake MASLOC, YouStart, NAB, stimulus or govt grant SMS",
        "pattern": (
            r"(?:masloc|youstart|nef ghana"
            r"|youth (?:employment|enterprise)"
            r"|government (?:grant|loan|stimulus|fund|relief)"
            r"|approved (?:for )?(?:a )?(?:government )?(?:grant|loan|fund)"
            r"|ministry of finance.*loan"
            r"|ghana government.*ghs)"
        ),
    },

    # ── Ghanaian banks ──────────────────────────────────────────────
    {
        "id": "gh_bank_impersonation",
        "name": "Ghanaian bank impersonation",
        "weight": 30,
        "severity": "high",
        "region": "gh",
        "category": "Financial fraud",
        "desc": "GCB, Absa, Fidelity, Stanbic, Ecobank, CalBank, Access, Zenith, UBA",
        "pattern": (
            r"(?:(?:gcb|absa|fidelity|stanbic|ecobank|calbank"
            r"|access bank|zenith bank|uba ghana|republic bank"
            r"|agricultural development bank|adb)"
            r" (?:ghana|account|momo|card|online|mobile|suspended|verify|update|blocked|alert)"
            r"|(?:your |dear )?(?:gcb|absa|fidelity|stanbic|ecobank|calbank"
            r"|access bank|zenith|uba) (?:account|card|transaction|customer))"
        ),
    },
    {
        "id": "gh_investment_scam",
        "name": "Investment / trading scam",
        "weight": 28,
        "severity": "high",
        "region": "gh",
        "category": "Financial fraud",
        "desc": "Ponzi, forex signals, crypto, fake SSNIT pension payouts",
        "pattern": (
            r"(?:double (?:your )?(?:money|investment|returns?)"
            r"|guaranteed (?:returns?|profit|income|investment)"
            r"|invest (?:ghs|gh|cedis|\d).*per (?:day|week|month)"
            r"|forex (?:profit|returns|signal|trading).*ghs"
            r"|crypto (?:trading|investment).*guaranteed"
            r"|ssnit (?:refund|pension|payout|payment)"
            r"|pension (?:fund|refund).*ssnit)"
        ),
    },

    # ── Delivery / customs ──────────────────────────────────────────
    {
        "id": "gh_delivery_customs",
        "name": "Ghana delivery / customs duty scam",
        "weight": 25,
        "severity": "high",
        "region": "gh",
        "category": "Delivery fraud",
        "desc": "Fake GhanaPost, KIA customs fee, DHL/FedEx for Ghana",
        "pattern": (
            r"(?:ghanapost|ghana post|ghana customs"
            r"|customs (?:duty|fee|clearance|charge).*ghs"
            r"|(?:ghs|gh[c¢]) \d[\d,.]*.*(?:customs|duty|clearance|release|delivery fee)"
            r"|your (?:package|parcel|shipment) (?:is held|on hold|at customs|detained).*ghs"
            r"|pay (?:ghs|cedis) \d.*release"
            r"|ghana airport.*package)"
        ),
    },

    # ── SIM swap / KYC ─────────────────────────────────────────────
    {
        "id": "sim_kyc_fraud",
        "name": "SIM swap / fake KYC update",
        "weight": 30,
        "severity": "high",
        "region": "gh",
        "category": "SIM / KYC fraud",
        "desc": "Fake SIM re-registration, NCA/NIA KYC deadline, SIM block",
        "pattern": (
            r"(?:sim (?:registration|re.?registration|swap|update|blocked|deactivat)"
            r"|kyc (?:update|verification|compliance|deadline)"
            r"|nia.*sim|ghana card.*sim"
            r"|update (?:your )?(?:sim|kyc|nia) (?:details|information|record|data)"
            r"|sim.*expire|re.?register (?:your )?sim|nca.*sim)"
        ),
    },

    # ── Job / recruitment scams ─────────────────────────────────────
    {
        "id": "gh_job_scam",
        "name": "Fake job / government recruitment scam",
        "weight": 22,
        "severity": "med",
        "region": "gh",
        "category": "Job fraud",
        "desc": "Fake GNPC, Cocobod, GES, police, army, health service jobs",
        "pattern": (
            r"(?:gnpc|cocobod|ghana cocoa board|ges "
            r"|ghana education service"
            r"|ghana police service.*recrui|ghana army.*recrui"
            r"|ghana navy.*recrui|ghana immigration.*recrui"
            r"|ghana health service.*recrui"
            r"|job (?:offer|opportunity).*ghs.*month"
            r"|salary.*ghs.*\d,\d{3}"
            r"|recruitment.*fee.*ghs"
            r"|apply.*ghs.*processing)"
        ),
    },

    # ── Ghanaian slang phishing ─────────────────────────────────────
    {
        "id": "gh_slang_phishing",
        "name": "Ghanaian slang phishing patterns",
        "weight": 20,
        "severity": "med",
        "region": "gh",
        "category": "Slang / dialect",
        "desc": "Twi-influenced and street-language MoMo scam phrases",
        "pattern": (
            r"(?:wo.*momo|me.*momo|obia.*momo"
            r"|send me (?:the )?money.*mistake"
            r"|i (?:mistakenly|accidentally) sent"
            r"|charle.*momo|bossu.*momo|massa.*send"
            r"|herh.*momo|bro.*wrong number.*send back"
            r"|my guy.*momo|correct guy.*transfer)"
        ),
    },
]
