type Point = { name: string; count: number };
const colors: Record<string, string> = {
  Critical: "#ff5c6c",
  High: "#ff9b65",
  Medium: "#e8c866",
  Low: "#45d6b0",
  Informational: "#73b8e4",
};

export default function SeverityChart({ data }: { data: Point[] }) {
  const maximum = Math.max(...data.map((item) => item.count), 0);

  return (
    <div className="severity-chart" role="list" aria-label="Findings by severity">
      {data.map((item) => {
        const color = colors[item.name] || "#39ff88";
        return (
          <div className="severity-chart-row" role="listitem" key={item.name}>
            <span className="severity-chart-label">{item.name}</span>
            <div
              className="severity-chart-track"
              role="meter"
              aria-label={`${item.name} findings`}
              aria-valuemin={0}
              aria-valuemax={maximum || 1}
              aria-valuenow={item.count}
              aria-valuetext={`${item.count} ${item.name} findings`}
            >
              <span
                className="severity-chart-fill"
                aria-hidden="true"
                style={{
                  width: `${maximum ? (item.count / maximum) * 100 : 0}%`,
                  backgroundColor: color,
                }}
              />
            </div>
            <strong className="severity-chart-count">{item.count}</strong>
          </div>
        );
      })}
    </div>
  );
}
