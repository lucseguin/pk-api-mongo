module.exports = {
    search:{
        "mappings": {
            "dynamic": false,
            "fields": {
                "options": {
                    "fields": {
                        "value": {
                            "type": "string"
                        }
                    },
                    "type": "document"
                }
            }
        },
        "name": "default"
    } ,
    groups:{
        user:{
            label: "Utilisateur",
            name: "user",
            protected: true,
            hidden: false,
            settings: {
                options: 39184
            }
        },
        bearer:{
            label: "Brancardier",
            name: "bearer",
            protected: true,
            hidden: false,
            settings: {
                options: 770
            }
        },
        cleaner:{
            label: "Nettoyeur",
            name: "cleaner",
            protected: true,
            hidden: false,
            settings: {
                options:12290
            }
        },
        admin:{
            label: "Administrateur de site",
            name: "admin",
            protected: true,
            hidden: false,
            settings: {
                options: 16768477
            }
        },
        management:{
            label: "Gestionnaire",
            name: "management",
            protected: true,
            hidden: false,
            settings: {
                options: 200988
            }
        },
        coodinator:{
            label: "Coordonateur",
            name: "coordinator",
            protected: true,
            hidden: false,
            settings: {
                options: 69908
            }
        },
        sysadmin:{
            label: "Administrateur organisationnel",
            name: "sysadmin",
            protected: true,
            hidden: true,
            settings: {
                options: 16777216
            }
        }
    },
    settings: {
        cleaner: {  
            module: "cleaner",
            settings: {
                request: {
                    properties: []
                },
                algos: [{
                    _id: "5f0cbe9a1c371db473256522",
                    name: "Round-Robin",
                    label: "Round-Robin",
                    description: "Les demandes vont être directement assigner au prochain brancardiers disponible, selon les conditions de la demande."
                }, {
                    _id: "5f0cbee41c371db473256523",
                    name: "Notify-Accept",
                    label: "Notify-Accept",
                    description: "Un notification d'une nouvelle demande sera envoyé à tous les brancardiers qui rencontre les conditions de la demande, afin qu'un d'entre eux accepte la demande."
                }],
                selectedAlgo: "Notify-Accept",
                useShifts: true,
                shifts: [{
                    _id: "5f0cbfff1c371db473256524",
                    from: "00:00",
                    to: "08:00"
                }, {
                    _id: "5f0cc01d1c371db473256525",
                    from: "08:00",
                    to: "16:00"
                }, {
                    _id: "5f0cc0481c371db473256527",
                    from: "16:00",
                    to: "\"00:00"
                }],
                useSectors: true,
                serviceLevel: "00:30:00"
            }
        },
        bearer: {
            module: "bearer",
            settings: {
                request: {
                    properties: []
                },
                algos: [{
                    _id: "5f0cbe9a1c371db473256522",
                    name: "Round-Robin",
                    label: "Round-Robin",
                    description: "Les demandes vont être directement assigner au prochain brancardiers disponible, selon les conditions de la demande."
                }, {
                    _id: "5f0cbee41c371db473256523",
                    name: "Notify-Accept",
                    label: "Notify-Accept",
                    description: "Un notification d'une nouvelle demande sera envoyé à tous les brancardiers qui rencontre les conditions de la demande, afin qu'un d'entre eux accepte la demande."
                }],
                selectedAlgo: "Notify-Accept",
                useShifts: true,
                shifts: [{
                    _id: "5f0cbfff1c371db473256524",
                    from: "00:00",
                    to: "08:00"
                }, {
                    _id: "5f0cc01d1c371db473256525",
                    from: "08:00",
                    to: "16:00"
                }, {
                    _id: "5f0cc0481c371db473256527",
                    from: "16:00",
                    to: "00:00"
                }],
                useSectors: true,
                serviceLevel: "00:45:00"
            }
        },
        visitor: {
            module: "visitor",
            settings: {
                request: {
                    properties: []
                },
                apikey:''
            }
        },
        config: {
            module: "config",
            settings: {
                licence: "",
                notif: {
                    bearer: "",
                    cleaner: ""
                }
            }
        }
    },

}