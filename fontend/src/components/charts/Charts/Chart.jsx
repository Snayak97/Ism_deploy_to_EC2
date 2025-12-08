import React from "react";
import {
  AreaChart,
  Area,
  XAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

const data = [
  { name: "January", Total: 1200 },
  { name: "February", Total: 2100 },
  { name: "March", Total: 800 },
  { name: "April", Total: 1600 },
  { name: "May", Total: 900 },
  { name: "June", Total: 1700 },
];

const Chart = ({ title }) => {
  return (
    <div
      aria-label={title}
      role="img"
      className="h-96 md:h-[400px] flex flex-col shadow-md dark:shadow-lg p-4 sm:p-6 rounded-xl text-gray-600 dark:text-gray-200 bg-white dark:bg-neutral-900 w-full hover:scale-102 transition transform duration-300 ease-in-out dark:hover:border-gray-300 dark:hover:shadow-[0_0_10px_2px_rgba(255,255,255,0.7)] dark:border-1 dark:border-transparent"
    >
      <h2 className="text-base font-semibold mb-3">{title}</h2>
      <div className="flex-grow">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart
            data={data}
            margin={{ top: 10, right: 30, left: 0, bottom: 0 }}
          >
            <defs>
              <linearGradient id="total" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#8884d8" stopOpacity={0.8} />
                <stop offset="95%" stopColor="#8884d8" stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="name" stroke="#999" />
            <CartesianGrid strokeDasharray="3 3" stroke="#e4e1e1" />
            <Tooltip />
            <Area
              type="monotone"
              dataKey="Total"
              stroke="#8884d8"
              fillOpacity={1}
              fill="url(#total)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export default Chart;
