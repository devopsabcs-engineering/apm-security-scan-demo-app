export default function Home() {
  return (
    <main>
      <h1>APM Demo App 001</h1>
      <p>Next.js with Unicode injection violations for APM Security scanning.</p>
      <pre>{JSON.stringify({
        app: "apm-demo-app-001",
        framework: "Next.js 15",
        description: "APM Security Demo — Unicode Injection Violations"
      }, null, 2)}</pre>
    </main>
  );
}
