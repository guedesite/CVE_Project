import {Box, Fade} from "@mui/material";
import {memo, useState} from "react";
import {ClimbingBoxLoader} from "react-spinners";
import toast from "react-hot-toast";

interface TCVE {
    cve_id:string,
    published_date:string,
    score:number,
    description:string,
    articles: Array<{
        title:string,
        url: string,
    }>
}

export const HomePage = memo(() => {

    const [searchQuery, setSearchQuery] = useState('');
    const [loading, setLoading] = useState(false);
    const [cveResults, setCveResults] = useState<Array<TCVE>>([]);
    const [error, setError] = useState('');

    const mockCVEData:Record<string, Array<TCVE>> = {
        'express': [
            {
                cve_id: 'CVE-2024-0001',
                published_date: '2024-01-15 10:00:00',
                score: 8.2,
                description: 'Cross-site scripting vulnerability in Express.js middleware that allows remote attackers to inject arbitrary web script or HTML.',
                articles: [
                    { title: 'Express.js Security Advisory', url: 'https://security.express.js' },
                    { title: 'CVE Analysis Report', url: 'https://example.com/analysis' }
                ]
            },
            {
                cve_id: 'CVE-2023-0445',
                published_date: '2023-12-08 14:30:00',
                score: 5.8,
                description: 'Denial of service vulnerability affecting Express.js applications when handling malformed requests.',
                articles: [
                    { title: 'DoS Attack Prevention Guide', url: 'https://example.com/dos-guide' }
                ]
            },
            {
                cve_id: 'CVE-2024-0001',
                published_date: '2024-01-15 10:00:00',
                score: 8.2,
                description: 'Cross-site scripting vulnerability in Express.js middleware that allows remote attackers to inject arbitrary web script or HTML.',
                articles: [
                    { title: 'Express.js Security Advisory', url: 'https://security.express.js' },
                    { title: 'CVE Analysis Report', url: 'https://example.com/analysis' }
                ]
            },
            {
                cve_id: 'CVE-2023-0445',
                published_date: '2023-12-08 14:30:00',
                score: 5.8,
                description: 'Denial of service vulnerability affecting Express.js applications when handling malformed requests.',
                articles: [
                    { title: 'DoS Attack Prevention Guide', url: 'https://example.com/dos-guide' }
                ]
            }
        ],
        'lodash': [
            {
                cve_id: 'CVE-2024-0123',
                published_date: '2024-02-20 09:15:00',
                score: 9.1,
                description: 'Critical prototype pollution vulnerability in Lodash library allowing arbitrary code execution.',
                articles: [
                    { title: 'Lodash Prototype Pollution Fix', url: 'https://lodash.com/security' },
                    { title: 'NPM Security Alert', url: 'https://npm.security.com' }
                ]
            }
        ]
    };

    const getSeverityColor = (score:number) => {
        if (score >= 9.0) return '#f44336';
        if (score >= 7.0) return '#ff9800';
        if (score >= 4.0) return '#2196f3';
        return '#4caf50';
    };

    const getSeverityText = (score:number) => {
        if (score >= 9.0) return 'CRITIQUE';
        if (score >= 7.0) return 'ÉLEVÉ';
        if (score >= 4.0) return 'MOYEN';
        return 'FAIBLE';
    };

    const handleSearch = async () => {
        if (!searchQuery.trim()) {
            setError('Veuillez saisir un nom de librairie');
            return;
        }

        setLoading(true);
        setError('');
        setCveResults([]);

        const [library, version] = searchQuery.split(':');
        const response = await fetch("/getCve", {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                cve:[{name:library, version:version}]
            })
        });

        if(response.status == 200) {
            const json = await response.json() as any[];
            if(json.length == 0) {
                setError(`Aucune CVE trouvée pour "${searchQuery}"`);
            }else {
                const output:Array<TCVE> = [];
                json.forEach((cves:any[]) => {
                    cves.forEach((cve) => {
                        output.push({
                            cve_id: cve.cve_id,
                            description: cve.description,
                            articles: [],
                            score: cve.cvss_score,
                            published_date: cve.published_date
                        })
                    });
                });
                setCveResults(output)
            }
        } else {
            setError(`Une erreur est survenue pendant la requête.`);
        }
        setLoading(false);

    };

    const handleKeyPress = (event:any) => {
        if (event.key === 'Enter') {
            handleSearch();
        }
    };

    return (
        <div style={{
            maxWidth: '1200px',
            margin: '0 auto',
            padding: '32px 16px',
            fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
        }}>
            <Fade in={loading} >
                <Box sx={{
                    backgroundColor: "rgba(0,0,0,0.2)",
                    position: "absolute",
                    zIndex:"9",
                    inset:"0px 0px 0px 0px",
                    display:"flex",
                    justifyContent:"center",
                    alignItems:"center"
                }}>
                    <ClimbingBoxLoader size={30} color={"#444"}  />
                </Box>
            </Fade>
            {/* Header */}
            <div style={{ textAlign: 'center', marginBottom: '48px' }}>
                <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    marginBottom: '16px',
                    gap: '12px'
                }}>
                    <div style={{
                        width: '40px',
                        height: '40px',
                        backgroundColor: '#1976d2',
                        borderRadius: '50%',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: 'white',
                        fontSize: '20px',
                        fontWeight: 'bold'
                    }}>
                        🛡️
                    </div>
                    <h1 style={{
                        fontSize: '2.5rem',
                        fontWeight: 'bold',
                        margin: 0,
                        color: '#1a1a1a'
                    }}>
                        CVE Scanner
                    </h1>
                </div>
                <h2 style={{
                    fontSize: '1.25rem',
                    color: '#666',
                    marginBottom: '32px',
                    fontWeight: 'normal'
                }}>
                    Analysez les vulnérabilités de sécurité de vos dépendances
                </h2>

                {/* Search Section */}
                <div style={{
                    backgroundColor: 'white',
                    padding: '24px',
                    borderRadius: '12px',
                    boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
                    maxWidth: '600px',
                    margin: '0 auto'
                }}>
                    <div style={{ display: 'flex', gap: '12px', marginBottom: '16px' }}>
                        <div style={{ flex: 1, position: 'relative' }}>
                            <input
                                type="text"
                                placeholder="ex: express ou express:4.18.0"
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                                onKeyPress={handleKeyPress}
                                style={{
                                    width: '100%',
                                    padding: '12px 16px 12px 40px',
                                    border: '2px solid #e0e0e0',
                                    borderRadius: '8px',
                                    fontSize: '16px',
                                    outline: 'none',
                                    transition: 'border-color 0.2s',
                                    boxSizing: 'border-box'
                                }}
                                onFocus={(e) => e.target.style.borderColor = '#1976d2'}
                                onBlur={(e) => e.target.style.borderColor = '#e0e0e0'}
                            />
                            <span style={{
                                position: 'absolute',
                                left: '12px',
                                top: '50%',
                                transform: 'translateY(-50%)',
                                color: '#666',
                                fontSize: '18px'
                            }}>
                🔍
              </span>
                        </div>
                        <button
                            onClick={handleSearch}
                            disabled={loading}
                            style={{
                                padding: '12px 24px',
                                backgroundColor: loading ? '#ccc' : '#1976d2',
                                color: 'white',
                                border: 'none',
                                borderRadius: '8px',
                                fontSize: '16px',
                                fontWeight: '500',
                                cursor: loading ? 'not-allowed' : 'pointer',
                                minWidth: '120px',
                                transition: 'background-color 0.2s'
                            }}
                        >
                            {loading ? '🔄 Analyse...' : 'Analyser'}
                        </button>
                    </div>

                    <p style={{
                        fontSize: '14px',
                        color: '#666',
                        margin: 0,
                        textAlign: 'left'
                    }}>
                        💡 Utilisez le format "librairie:version" pour spécifier une version (ex: express:4.18.0)
                    </p>
                </div>
            </div>

            {/* Error Display */}
            {error && (
                <div style={{
                    backgroundColor: '#fff3cd',
                    border: '1px solid #ffeaa7',
                    color: '#856404',
                    padding: '12px 16px',
                    borderRadius: '8px',
                    marginBottom: '24px'
                }}>
                    ⚠️ {error}
                </div>
            )}

            {/* Results Section */}
            {cveResults.length > 0 && (
                <div>
                    <h3 style={{
                        fontSize: '1.5rem',
                        marginBottom: '24px',
                        color: '#1a1a1a'
                    }}>
                        Vulnérabilités détectées ({cveResults.length})
                    </h3>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                        {cveResults.map((cve, index) => (
                            <div key={index} style={{
                                backgroundColor: 'white',
                                borderRadius: '12px',
                                padding: '24px',
                                boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
                                border: `3px solid ${getSeverityColor(cve.score)}20`
                            }}>
                                <div style={{
                                    display: 'flex',
                                    justifyContent: 'space-between',
                                    alignItems: 'flex-start',
                                    marginBottom: '16px',
                                    flexWrap: 'wrap',
                                    gap: '16px'
                                }}>
                                    <div style={{ flex: 1 }}>
                                        <h4 style={{
                                            fontSize: '1.25rem',
                                            fontWeight: 'bold',
                                            margin: '0 0 8px 0',
                                            color: '#1a1a1a'
                                        }}>
                                            {cve.cve_id}
                                        </h4>
                                        <p style={{
                                            fontSize: '14px',
                                            color: '#666',
                                            margin: 0
                                        }}>
                                            Publié le: {new Date(cve.published_date).toLocaleDateString('fr-FR')}
                                        </p>
                                    </div>

                                    <div style={{
                                        backgroundColor: getSeverityColor(cve.score),
                                        color: 'white',
                                        padding: '8px 16px',
                                        borderRadius: '20px',
                                        fontSize: '14px',
                                        fontWeight: 'bold',
                                        display: 'flex',
                                        alignItems: 'center',
                                        gap: '6px'
                                    }}>
                                        ⚠️ {getSeverityText(cve.score)} ({cve.score})
                                    </div>
                                </div>

                                <p style={{
                                    fontSize: '16px',
                                    lineHeight: '1.6',
                                    color: '#333',
                                    marginBottom: '20px'
                                }}>
                                    {cve.description}
                                </p>

                                {cve.articles && cve.articles.length > 0 && (
                                    <div>
                                        <hr style={{
                                            border: 'none',
                                            borderTop: '1px solid #e0e0e0',
                                            margin: '20px 0 16px 0'
                                        }} />
                                        <div style={{
                                            display: 'flex',
                                            alignItems: 'center',
                                            marginBottom: '12px',
                                            gap: '8px'
                                        }}>
                                            <span style={{ fontSize: '16px' }}>ℹ️</span>
                                            <h5 style={{
                                                fontSize: '16px',
                                                fontWeight: '600',
                                                margin: 0,
                                                color: '#1a1a1a'
                                            }}>
                                                Articles de référence
                                            </h5>
                                        </div>
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                            {cve.articles.map((article, articleIndex) => (
                                                <a
                                                    key={articleIndex}
                                                    href={article.url}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    style={{
                                                        display: 'flex',
                                                        alignItems: 'center',
                                                        gap: '8px',
                                                        color: '#1976d2',
                                                        textDecoration: 'none',
                                                        fontSize: '15px',
                                                        padding: '4px 0'
                                                    }}
                                                    onMouseOver={(e) => (e.target as HTMLElement).style.textDecoration = 'underline'}
                                                    onMouseOut={(e) => (e.target as HTMLElement).style.textDecoration = 'none'}
                                                >
                                                    <span style={{ fontSize: '14px' }}>🔗</span>
                                                    {article.title}
                                                </a>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Empty State */}
            {!loading && cveResults.length === 0 && !error && (
                <div style={{
                    textAlign: 'center',
                    padding: '64px 0',
                    color: '#666'
                }}>
                    <div style={{ fontSize: '80px', marginBottom: '16px' }}>🛡️</div>
                    <h3 style={{
                        fontSize: '1.25rem',
                        color: '#666',
                        fontWeight: 'normal'
                    }}>
                        Saisissez le nom d'une librairie pour commencer l'analyse
                    </h3>
                </div>
            )}
        </div>
    );
});

